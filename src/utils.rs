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

pub fn append_to_vec<T, I>(v: &mut Vec<T>, items: I)
where
    I: IntoIterator<Item = T>,
{
    items.into_iter().for_each(|item| {
        v.push(item);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_join() {
        assert_eq!(join(["a", "b", "c"].into_iter(), ' '), "a b c");
    }
}
