// Package schema describes the shape of every format PenSec writes or reads
// that other programs depend on, so tests can pin them. A shape is one line
// per field: its dotted path, the encoding name and a coarse type.
package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Shape returns the fields of v's type as sorted lines "path type". tag is
// the struct tag used for names ("json" or "yaml"); "-" fields are skipped,
// as the encoders skip them.
func Shape(v any, tag string) []string {
	var out []string
	walk(reflect.TypeOf(v), "", tag, map[reflect.Type]bool{}, &out)
	sort.Strings(out)
	return out
}

var rawMessage = reflect.TypeOf(json.RawMessage{})

func walk(t reflect.Type, path, tag string, seen map[reflect.Type]bool, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessage {
		*out = append(*out, path+" raw")
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		if seen[t] {
			*out = append(*out, path+" recursive:"+t.Name())
			return
		}
		seen[t] = true
		defer delete(seen, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get(tag), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				// Untagged fields keep their Go name in JSON and are
				// lowercased by the YAML encoder.
				name = f.Name
				if tag == "yaml" {
					name = strings.ToLower(f.Name)
				}
			}
			p := name
			if path != "" {
				p = path + "." + name
			}
			walk(f.Type, p, tag, seen, out)
		}
	case reflect.Slice, reflect.Array:
		walk(t.Elem(), path+"[]", tag, seen, out)
	case reflect.Map:
		walk(t.Elem(), path+"{}", tag, seen, out)
	case reflect.Interface:
		*out = append(*out, path+" any")
	default:
		*out = append(*out, fmt.Sprintf("%s %s", path, t.Kind()))
	}
}

// StripDescriptions removes "description" keys from a decoded JSON value,
// so wording changes do not count as schema changes.
func StripDescriptions(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if k != "description" {
				out[k] = StripDescriptions(e)
			}
		}
		return out
	case []any:
		for i := range x {
			x[i] = StripDescriptions(x[i])
		}
		return x
	}
	return v
}
