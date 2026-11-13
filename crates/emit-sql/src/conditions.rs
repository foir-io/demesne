use crate::Sql;
use crate::genfn::{GenFn, Language};
use crate::rls::conditions_fn;
use demesne_syntax::{Object, Relation, Repr, ViaConditions};
use std::fmt::Write as _;

const SPHERE_RADIUS_KM: &str = "6371.0";

const INSTANT_FN: &str = "demesne_instant";

fn compared(op: &str, c: &ViaConditions) -> String {
    let (num, txt, at) = (&c.num_col, &c.txt_col, &c.at_col);
    format!("CASE WHEN c.{num} IS NOT NULL THEN c.{num} {op} x.num WHEN c.{at} IS NOT NULL THEN c.{at} {op} x.at ELSE c.{txt} {op} x.txt COLLATE \"C\" END")
}

fn ordered(op: &str, c: &ViaConditions) -> String {
    let (num, at) = (&c.num_col, &c.at_col);
    format!("CASE WHEN c.{num} IS NOT NULL THEN c.{num} {op} x.num WHEN c.{at} IS NOT NULL THEN c.{at} {op} x.at END")
}

fn among_the_callers(c: &ViaConditions) -> String {
    let (num, txt) = (&c.num_col, &c.txt_col);
    format!(
        "CASE WHEN jsonb_typeof(x.v) = 'array' THEN EXISTS (SELECT 1 FROM jsonb_array_elements(x.v) e WHERE (jsonb_typeof(e) = 'number' AND (e #>> '{{}}')::double precision = c.{num}) OR (jsonb_typeof(e) = 'string' AND (e #>> '{{}}') = c.{txt} COLLATE \"C\")) END"
    )
}

fn within_km(sql: &Sql, c: &ViaConditions) -> Option<String> {
    let (lat, lng) = c.point_cols.as_ref()?;
    let radius = &c.num_col;
    let in_range =
        format!("c.{lat} BETWEEN -90 AND 90 AND c.{lng} BETWEEN -180 AND 180 AND x.lat BETWEEN -90 AND 90 AND x.lng BETWEEN -180 AND 180 AND c.{radius} >= 0");
    if let Some(gis) = sql.s.extensions.iter().find(|e| e.name == "postgis").map(demesne_syntax::Extension::schema) {
        let point = |lng: &str, lat: &str| format!("{gis}.ST_SetSRID({gis}.ST_MakePoint({lng}, {lat}), 4326)::{gis}.geography");
        return Some(format!(
            "CASE WHEN {in_range} THEN {gis}.ST_DWithin({}, {}, c.{radius} * 1000.0) END",
            point(&format!("c.{lng}"), &format!("c.{lat}")),
            point("x.lng", "x.lat")
        ));
    }
    let a = format!("(sin(radians(x.lat - c.{lat}) / 2) ^ 2 + cos(radians(c.{lat})) * cos(radians(x.lat)) * sin(radians(x.lng - c.{lng}) / 2) ^ 2)");
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
        let includes = format!("x.scalar = ANY(c.{list})");
        add("includes", includes.clone());
        add("not_includes", format!("CASE WHEN x.scalar IS NOT NULL AND c.{list} IS NOT NULL THEN NOT ({includes}) END"));
    }
    let text_tests = [
        ("contains", format!("strpos(c.{txt}, x.txt) > 0")),
        ("prefix", format!("starts_with(c.{txt}, x.txt)")),
        ("suffix", format!("right(c.{txt}, length(x.txt)) = x.txt COLLATE \"C\"")),
        ("caller_contains", format!("strpos(x.txt, c.{txt}) > 0")),
        ("caller_prefix", format!("starts_with(x.txt, c.{txt})")),
        ("caller_suffix", format!("right(x.txt, length(c.{txt})) = c.{txt} COLLATE \"C\"")),
    ];
    for (name, holds) in text_tests {
        add(&format!("not_{name}"), format!("CASE WHEN x.txt IS NOT NULL AND c.{txt} IS NOT NULL THEN NOT ({holds}) END"));
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
            write!(cases, "\n      WHEN '{name}' THEN {holds}").expect("fmt::Write for String never fails");
        }
        let key_arg = if c.key.is_some() { ", p_key text" } else { "" };
        let keyed = c.key.as_ref().map(|k| format!(" AND c.{k} = p_key")).unwrap_or_default();
        let term = &c.term_col;
        let caller = format!(
            "SELECT p_values -> c.{term} AS v,\n      CASE WHEN jsonb_typeof(p_values -> c.{term}) = 'number' THEN (p_values ->> c.{term})::double precision END AS num,\n      CASE WHEN jsonb_typeof(p_values -> c.{term}) = 'string' THEN p_values ->> c.{term} END AS txt,\n      CASE WHEN jsonb_typeof(p_values -> c.{term}) = 'string' THEN {schema}.{INSTANT_FN}(p_values ->> c.{term}) END AS at,\n      CASE WHEN jsonb_typeof(p_values -> c.{term}) IN ('string', 'number') THEN p_values ->> c.{term} END AS scalar,\n      CASE WHEN jsonb_typeof(p_values -> c.{term} -> 'lat') = 'number' THEN (p_values -> c.{term} ->> 'lat')::double precision END AS lat,\n      CASE WHEN jsonb_typeof(p_values -> c.{term} -> 'lng') = 'number' THEN (p_values -> c.{term} ->> 'lng')::double precision END AS lng"
        );
        GenFn {
            name: conditions_fn(obj, r),
            sig: format!("p_object {}{key_arg}, p_values jsonb", self.s.id_type()),
            raw_body: true,
            body: format!(
                "  SELECT CASE WHEN p_object IS NULL THEN NULL WHEN bool_or(h.holds IS FALSE) THEN false WHEN bool_or(h.holds IS NULL) THEN NULL ELSE true END\n  FROM (\n    SELECT (CASE c.{op}{cases}\n    END) AS holds\n    FROM {table} c CROSS JOIN LATERAL (\n      {caller}\n    ) x\n    WHERE c.{object} = p_object{keyed}\n  ) h;",
                table = c.table,
                object = c.object_col,
                op = c.op_col
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
