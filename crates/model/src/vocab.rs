use demesne_runtime as rt;
use demesne_syntax::Vocabulary;

fn l(v: &[String]) -> rt::Strs {
    rt::owned_list(v.iter().cloned())
}

#[must_use]
pub fn to_runtime(v: &Vocabulary) -> rt::Vocabulary {
    rt::Vocabulary {
        name: rt::owned(v.name.clone()),
        permissions: l(&v.permissions),
        implications: v
            .implications
            .iter()
            .map(|im| rt::Implication { perm: rt::owned(im.perm.clone()), set: l(&im.set), star: im.star })
            .collect::<Vec<_>>()
            .into(),
        presets: v
            .presets
            .iter()
            .map(|p| rt::Preset { name: rt::owned(p.name.clone()), level: rt::owned(p.level.clone().unwrap_or_default()), set: l(&p.set), star: p.star })
            .collect::<Vec<_>>()
            .into(),
        rank: l(&v.rank),
    }
}
