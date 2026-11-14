use crate::Sql;
use crate::genfn::{GenFn, Language};
use crate::rls::conditions_fn;
use demesne_syntax::{Object, Relation, Repr, ViaConditions};
use std::fmt::Write as _;

const SPHERE_RADIUS_KM: &str = "6371.0";

const INSTANT_FN: &str = "demesne_instant";

fn compared(op: &str, c: &ViaConditions) -> String {
    let (num, txt, at) = (&c.num_col, &c.txt_col, &c.at_col);
    format!("CASE WHEN c.{num} IS NOT NULL THEN c.{num} {op} x_num WHEN c.{at} IS NOT NULL THEN c.{at} {op} x_at ELSE c.{txt} {op} x_txt COLLATE \"C\" END")
}

fn ordered(op: &str, c: &ViaConditions) -> String {
    let (num, at) = (&c.num_col, &c.at_col);
    format!("CASE WHEN c.{num} IS NOT NULL THEN c.{num} {op} x_num WHEN c.{at} IS NOT NULL THEN c.{at} {op} x_at END")
}

fn among_the_callers(c: &ViaConditions) -> String {
    let (num, txt) = (&c.num_col, &c.txt_col);
    format!(
        "CASE WHEN jsonb_typeof(x_v) = 'array' THEN EXISTS (SELECT 1 FROM jsonb_array_elements(x_v) e WHERE (jsonb_typeof(e) = 'number' AND (e #>> '{{}}')::double precision = c.{num}) OR (jsonb_typeof(e) = 'string' AND (e #>> '{{}}') = c.{txt} COLLATE \"C\")) END"
    )
}

fn within_km(sql: &Sql, c: &ViaConditions) -> Option<String> {
    let (lat, lng) = c.point_cols.as_ref()?;
    let radius = &c.num_col;
    let in_range =
        format!("c.{lat} BETWEEN -90 AND 90 AND c.{lng} BETWEEN -180 AND 180 AND x_lat BETWEEN -90 AND 90 AND x_lng BETWEEN -180 AND 180 AND c.{radius} >= 0");
    if let Some(gis) = sql.s.extensions.iter().find(|e| e.name == "postgis").map(demesne_syntax::Extension::schema) {
        let point = |lng: &str, lat: &str| format!("{gis}.ST_SetSRID({gis}.ST_MakePoint({lng}, {lat}), 4326)::{gis}.geography");
        return Some(format!(
            "CASE WHEN {in_range} THEN {gis}.ST_DWithin({}, {}, c.{radius} * 1000.0) END",
            point(&format!("c.{lng}"), &format!("c.{lat}")),
            point("x_lng", "x_lat")
        ));
    }
    let a = format!("(sin(radians(x_lat - c.{lat}) / 2) ^ 2 + cos(radians(c.{lat})) * cos(radians(x_lat)) * sin(radians(x_lng - c.{lng}) / 2) ^ 2)");
    Some(format!("CASE WHEN {in_range} THEN {SPHERE_RADIUS_KM} * 2 * atan2(sqrt(least(1.0, {a})), sqrt(greatest(0.0, 1.0 - {a}))) <= c.{radius} END"))
}

fn operators(sql: &Sql, c: &ViaConditions) -> Vec<(String, String)> {
    let txt = &c.txt_col;
    let mut ops: Vec<(String, String)> = Vec::new();
    let mut add = |name: &str, holds: String| ops.push((name.to_string(), holds));
    add("eq", compared("=", c));
    add("ne", compared("<>", c));
    for (name, op) in [("lt", "<"), ("le", "<="), ("gt", ">"), ("ge", ">=")] {
        add(name, ordered(op, c));
    }
    add("in", among_the_callers(c));
    add("not_in", format!("NOT ({})", among_the_callers(c)));
    if let Some(list) = &c.list_col {
        let includes = format!("x_scalar = ANY(c.{list})");
        add("includes", includes.clone());
        add("not_includes", format!("CASE WHEN x_scalar IS NOT NULL AND c.{list} IS NOT NULL THEN NOT ({includes}) END"));
    }
    let text_tests = [
        ("contains", format!("strpos(c.{txt}, x_txt) > 0")),
        ("prefix", format!("starts_with(c.{txt}, x_txt)")),
        ("suffix", format!("right(c.{txt}, length(x_txt)) = x_txt COLLATE \"C\"")),
        ("caller_contains", format!("strpos(x_txt, c.{txt}) > 0")),
        ("caller_prefix", format!("starts_with(x_txt, c.{txt})")),
        ("caller_suffix", format!("right(x_txt, length(c.{txt})) = c.{txt} COLLATE \"C\"")),
    ];
    for (name, holds) in text_tests {
        add(&format!("not_{name}"), format!("CASE WHEN x_txt IS NOT NULL AND c.{txt} IS NOT NULL THEN NOT ({holds}) END"));
        add(name, holds);
    }
    add("not_before", format!("now() >= c.{}", c.at_col));
    add("not_after", format!("now() <= c.{}", c.at_col));
    if let Some(holds) = within_km(sql, c) {
        add("within_km", holds);
    }
    ops
}

fn instant_definer() -> GenFn {
    GenFn {
        name: INSTANT_FN.into(),
        sig: "p_text text".into(),
        returns: "timestamptz".into(),
        strict: true,
        raw_body: true,
        language: Language::Plpgsql,
        body: "BEGIN\n  IF p_text !~ '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})$' THEN\n    RETURN NULL;\n  END IF;\n  RETURN p_text::timestamptz;\nEXCEPTION WHEN others THEN\n  RETURN NULL;\nEND".into(),
        ..Default::default()
    }
}

impl Sql<'_> {
    fn conditions_definer(&self, obj: &Object, r: &Relation, c: &ViaConditions) -> GenFn {
        let schema = self.s.definer_schema();
        let mut cases = String::new();
        for (name, holds) in operators(self, c) {
            write!(cases, "\n      WHEN '{name}' THEN holds := {holds};").expect("fmt::Write for String never fails");
        }
        let key_arg = if c.key.is_some() { ", p_key text" } else { "" };
        let keyed = c.key.as_ref().map(|k| format!(" AND c.{k} = p_key")).unwrap_or_default();
        let read = |name: &str, value: &str| format!("    {name} := {value};\n");
        let caller = [
            read("x_v", &format!("p_values -> c.{}", c.term_col)),
            read("x_num", "CASE WHEN jsonb_typeof(x_v) = 'number' THEN (x_v #>> '{}')::double precision END"),
            read("x_txt", "CASE WHEN jsonb_typeof(x_v) = 'string' THEN x_v #>> '{}' END"),
            read("x_at", &format!("CASE WHEN c.{} IS NOT NULL AND x_txt IS NOT NULL THEN {schema}.{INSTANT_FN}(x_txt) END", c.at_col)),
            read("x_scalar", "CASE WHEN jsonb_typeof(x_v) IN ('string', 'number') THEN x_v #>> '{}' END"),
            read("x_lat", "CASE WHEN jsonb_typeof(x_v -> 'lat') = 'number' THEN (x_v ->> 'lat')::double precision END"),
            read("x_lng", "CASE WHEN jsonb_typeof(x_v -> 'lng') = 'number' THEN (x_v ->> 'lng')::double precision END"),
        ]
        .concat();
        GenFn {
            name: conditions_fn(obj, r),
            sig: format!("p_object {}{key_arg}, p_values jsonb", self.s.id_type()),
            raw_body: true,
            language: Language::Plpgsql,
            body: format!(
                "DECLARE\n  c record;\n  x_v jsonb;\n  x_num double precision;\n  x_txt text;\n  x_at timestamptz;\n  x_scalar text;\n  x_lat double precision;\n  x_lng double precision;\n  holds boolean;\n  undecided boolean := false;\nBEGIN\n  IF p_object IS NULL THEN\n    RETURN NULL;\n  END IF;\n  FOR c IN SELECT s.* FROM {table} s WHERE s.{object} = p_object{keyed} LOOP\n{caller}    CASE c.{op}{cases}\n      ELSE holds := NULL;\n    END CASE;\n    IF holds IS FALSE THEN\n      RETURN false;\n    END IF;\n    undecided := undecided OR holds IS NULL;\n  END LOOP;\n  RETURN CASE WHEN undecided THEN NULL ELSE true END;\nEND",
                table = c.table,
                object = c.object_col,
                op = c.op_col,
                keyed = keyed.replace(" AND c.", " AND s."),
            ),
            ..Default::default()
        }
    }

    pub(crate) fn conditions_definers(&self) -> Vec<GenFn> {
        let mut out = Vec::new();
        for (obj, r) in self.s.relations() {
            let Repr::Conditions(c) = &r.repr else { continue };
            if out.is_empty() {
                out.push(instant_definer());
            }
            out.push(self.conditions_definer(obj, r, c));
        }
        out
    }
}
