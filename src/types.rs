use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    I32,
    Bool,
    Void,
}

impl Type {
    pub fn is_numeric(&self) -> bool {
        matches!(self, Type::I32)
    }

    pub fn is_boolean(&self) -> bool {
        matches!(self, Type::Bool)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::I32 => write!(f, "i32"),
            Type::Bool => write!(f, "bool"),
            Type::Void => write!(f, "void"),
        }
    }
}
