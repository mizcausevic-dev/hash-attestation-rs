//! Validate values before JSON serializers can silently convert NaN or infinity to null.

use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant, Serializer,
};
use serde::Serialize;

pub(crate) fn check_finite<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    value.serialize(FiniteSerializer)
}

struct FiniteSerializer;
struct Compound;

type Error = serde_json::Error;

fn invalid_number() -> Error {
    <Error as serde::ser::Error>::custom("NaN and infinity are not valid JCS numbers")
}

impl Serializer for FiniteSerializer {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Compound;
    type SerializeTuple = Compound;
    type SerializeTupleStruct = Compound;
    type SerializeTupleVariant = Compound;
    type SerializeMap = Compound;
    type SerializeStruct = Compound;
    type SerializeStructVariant = Compound;

    fn serialize_bool(self, _: bool) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_i8(self, _: i8) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_i16(self, _: i16) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_i32(self, _: i32) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_i64(self, _: i64) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_i128(self, _: i128) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_u8(self, _: u8) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_u16(self, _: u16) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_u32(self, _: u32) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_u64(self, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_u128(self, _: u128) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_f32(self, value: f32) -> Result<(), Error> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(invalid_number())
        }
    }
    fn serialize_f64(self, value: f64) -> Result<(), Error> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(invalid_number())
        }
    }
    fn serialize_char(self, _: char) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_str(self, _: &str) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_bytes(self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_none(self) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Compound, Error> {
        Ok(Compound)
    }
    fn serialize_tuple(self, _: usize) -> Result<Compound, Error> {
        Ok(Compound)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Compound, Error> {
        Ok(Compound)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Compound, Error> {
        Ok(Compound)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Compound, Error> {
        Ok(Compound)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Compound, Error> {
        Ok(Compound)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Compound, Error> {
        Ok(Compound)
    }
    fn collect_str<T: ?Sized + std::fmt::Display>(self, _: &T) -> Result<(), Error> {
        Ok(())
    }
}

impl SerializeSeq for Compound {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        value.serialize(FiniteSerializer)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl SerializeTuple for Compound {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        value.serialize(FiniteSerializer)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl SerializeTupleStruct for Compound {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        value.serialize(FiniteSerializer)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl SerializeTupleVariant for Compound {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        value.serialize(FiniteSerializer)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl SerializeMap for Compound {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
        key.serialize(FiniteSerializer)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        value.serialize(FiniteSerializer)
    }
    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        key.serialize(FiniteSerializer)?;
        value.serialize(FiniteSerializer)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl SerializeStruct for Compound {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(FiniteSerializer)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl SerializeStructVariant for Compound {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(FiniteSerializer)
    }
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}
