use serde::{Deserialize, Deserializer};
pub fn join<'a, I, T>(mut str_iter: I, sep: char) -> String
where
    I: Iterator<Item = &'a T>,
    T: AsRef<str> + 'a + ?Sized,
{
    let mut result = String::default();
    if let Some(val) = str_iter.next() {
        result.push_str(val.as_ref());
    }
    str_iter.for_each(|chunk| {
        result.push(sep);
        result.push_str(chunk.as_ref());
    });
    return result;
}

pub fn deserialize_space_sep_vec<'de, D>(d: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;
    if let Some(space_delimited) = Option::<String>::deserialize(d)? {
        let entries = space_delimited
            .split(' ')
            .map(|s| Value::String(s.to_string()))
            .collect();
        let res = Vec::<String>::deserialize(Value::Array(entries)).map_err(Error::custom)?;
        Ok(Some(res))
    } else {
        // If the JSON value is null, use the default value.
        Ok(Some(Vec::default()))
    }
}

pub fn append_to_vec<T, I>(v: &mut Vec<T>, items: I)
where
    I: IntoIterator<Item = T>,
{
    items.into_iter().for_each(|item| {
        v.push(item);
    });
}
