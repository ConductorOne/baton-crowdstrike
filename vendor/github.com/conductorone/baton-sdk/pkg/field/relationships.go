package field

type Relationship int

const (
	RequiredTogether Relationship = iota + 1
	MutuallyExclusive
	AtLeastOne
)

type SchemaFieldRelationship struct {
	Kind   Relationship
	Fields []SchemaField
}

func FieldsRequiredTogether(fields ...SchemaField) SchemaFieldRelationship {
	return SchemaFieldRelationship{
		Kind:   RequiredTogether,
		Fields: fields,
	}
}

func FieldsMutuallyExclusive(fields ...SchemaField) SchemaFieldRelationship {
	return SchemaFieldRelationship{
		Kind:   MutuallyExclusive,
		Fields: fields,
	}
}

func FieldsAtLeastOneUsed(fields ...SchemaField) SchemaFieldRelationship {
	return SchemaFieldRelationship{
		Kind:   AtLeastOne,
		Fields: fields,
	}
}