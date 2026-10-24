use demesne_runtime as rt;
use demesne_syntax::Vocabulary;

pub fn to_runtime(v: &Vocabulary) -> rt::Vocabulary {
    rt::Vocabulary {
        name: v.name.clone(),
        permissions: v.permissions.clone(),
        implications: v
            .implications
            .iter()
            .map(|im| rt::Implication { perm: im.perm.clone(), set: im.set.clone(), star: im.star })
            .collect(),
        presets: v
            .presets
            .iter()
            .map(|p| rt::Preset { name: p.name.clone(), level: p.level.clone().unwrap_or_default(), set: p.set.clone(), star: p.star })
            .collect(),
        rank: v.rank.clone(),
    }
}
