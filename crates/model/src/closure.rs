//! The edge every relation over a closure table is read against, and the direction each relation reads it in.

use demesne_syntax::{Closure, Repr, Spec, ViaClosure};

/// Which way a closure relation reads the edge from the caller to the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The caller's node is the ancestor: the relation reaches rows at the node and beneath it.
    Down,
    /// The caller's node is the descendant: the relation reaches rows at the node and above it.
    Up,
}

/// The table a closure is maintained from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base<'a> {
    pub table: &'a str,
    pub id_col: &'a str,
    pub parent_col: &'a str,
}

/// One closure table as the spec fixes it: by its `closure` declaration, or by the first relation over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge<'a> {
    pub table: &'a str,
    pub ancestor_col: &'a str,
    pub descendant_col: &'a str,
    pub base: Option<Base<'a>>,
    pub declared: Option<&'a Closure>,
}

impl<'a> Edge<'a> {
    /// Returns the name the closure's generated functions and triggers start with.
    #[must_use]
    pub fn definer_base(&self) -> &'a str {
        self.declared.map_or(self.table, Closure::definer_base)
    }

    /// Returns the direction a relation naming `first` then `second` reads, or `None` when the columns are not this edge's.
    #[must_use]
    pub fn direction(&self, first: &str, second: &str) -> Option<Direction> {
        if first == self.ancestor_col && second == self.descendant_col {
            Some(Direction::Down)
        } else if first == self.descendant_col && second == self.ancestor_col {
            Some(Direction::Up)
        } else {
            None
        }
    }

    /// Returns the direction `relation` reads this edge in, or `None` when its columns are not this edge's.
    #[must_use]
    pub fn relation_direction(&self, relation: &ViaClosure) -> Option<Direction> {
        self.direction(&relation.ancestor_col, &relation.descendant_col)
    }
}

fn relation_base(c: &ViaClosure) -> Option<Base<'_>> {
    let table = c.base.as_deref()?;
    Some(Base { table, id_col: c.base_id.as_deref().unwrap_or(""), parent_col: c.base_parent.as_deref().unwrap_or("") })
}

/// Every relation over the closure `table`, in declaration order.
pub fn relations_over<'a>(s: &'a Spec, table: &'a str) -> impl Iterator<Item = &'a ViaClosure> {
    s.relations().filter_map(move |(_, r)| match &r.repr {
        Repr::Closure(c) if c.closure == table => Some(c),
        _ => None,
    })
}

/// Returns the edge of the closure `table`, or `None` when the spec neither declares it nor relates through it.
///
/// A `closure` declaration fixes the edge. Without one, the first relation over the table does, and the first
/// relation naming a `base` says what the closure is maintained from.
#[must_use]
pub fn edge<'a>(s: &'a Spec, table: &'a str) -> Option<Edge<'a>> {
    if let Some(c) = s.closure_by_table(table) {
        let base = c.base.as_ref().map(|b| Base { table: &b.table, id_col: &b.id_col, parent_col: &b.parent_col });
        return Some(Edge { table: &c.table, ancestor_col: &c.ancestor_col, descendant_col: &c.descendant_col, base, declared: Some(c) });
    }
    let first = relations_over(s, table).next()?;
    Some(Edge {
        table: &first.closure,
        ancestor_col: &first.ancestor_col,
        descendant_col: &first.descendant_col,
        base: relations_over(s, table).find_map(relation_base),
        declared: None,
    })
}

/// Every closure the spec relates through or declares, each once.
///
/// A closure some relation reads comes first, in the order the relations are declared, and a closure that is only
/// declared follows, in declaration order.
#[must_use]
pub fn edges(s: &Spec) -> Vec<Edge<'_>> {
    let related = s.relations().filter_map(|(_, r)| match &r.repr {
        Repr::Closure(c) => Some(c.closure.as_str()),
        _ => None,
    });
    let mut tables: Vec<&str> = Vec::new();
    for table in related.chain(s.closures.iter().map(|c| c.table.as_str())) {
        if !tables.contains(&table) {
            tables.push(table);
        }
    }
    tables.into_iter().filter_map(|t| edge(s, t)).collect()
}
