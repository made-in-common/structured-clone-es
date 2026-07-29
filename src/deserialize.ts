import {
  ARRAY,
  BIGINT,
  DATE,
  ERROR,
  MAP,
  OBJECT,
  PRIMITIVE,
  REGEXP,
  SET,
  VOID,
} from './types'

declare const self: typeof globalThis | undefined

const env = typeof self === 'object' ? self : globalThis

// Allow-lists of the ONLY constructors the deserializer may invoke by name.
// The serialized `name`/`type` string is attacker-controllable, so it must
// never be used to index into the global object directly: constructors such as
// `Function` would turn a serialized record into arbitrary executable code
// (`new Function(message)`), and other globals could be abused for DoS or
// unexpected side effects. Anything outside these sets is rejected.
const SAFE_ERROR_NAMES = new Set([
  'Error',
  'EvalError',
  'RangeError',
  'ReferenceError',
  'SyntaxError',
  'TypeError',
  'URIError',
  'AggregateError',
])

const SAFE_CONSTRUCTOR_NAMES = new Set([
  'Boolean',
  'Number',
  'String',
  'Int8Array',
  'Uint8Array',
  'Uint8ClampedArray',
  'Int16Array',
  'Uint16Array',
  'Int32Array',
  'Uint32Array',
  'Float16Array',
  'Float32Array',
  'Float64Array',
  'BigInt64Array',
  'BigUint64Array',
])

function deserializer($: Map<number, any>, _: any[]): (index: number) => any {
  const as = (out: any, index: number): any => {
    $.set(index, out)
    return out
  }

  const unpair = (index: number): any => {
    if ($.has(index))
      return $.get(index)

    const [type, value] = _[index]
    switch (type) {
      case PRIMITIVE:
      case VOID:
        return as(value, index)
      case ARRAY: {
        const arr = as([], index)
        for (const index of value)
          arr.push(unpair(index))
        return arr
      }
      case OBJECT: {
        const object = as({}, index)
        for (const [key, index] of value)
          object[unpair(key)] = unpair(index)
        return object
      }
      case DATE:
        return as(new Date(value), index)
      case REGEXP: {
        const { source, flags } = value
        return as(new RegExp(source, flags), index)
      }
      case MAP: {
        const map = as(new Map(), index)
        for (const [key, index] of value)
          map.set(unpair(key), unpair(index))
        return map
      }
      case SET: {
        const set = as(new Set(), index)
        for (const index of value)
          set.add(unpair(index))
        return set
      }
      case ERROR: {
        const { name, message } = value
        const Ctor = SAFE_ERROR_NAMES.has(name) ? (env as any)[name] : undefined
        // Fall back to a generic Error for unknown/unsafe names instead of
        // constructing an arbitrary global (e.g. `Function`).
        return as(new (Ctor ?? env.Error)(message), index)
      }
      case BIGINT:
        return as(BigInt(value), index)
      case 'BigInt':
        // eslint-disable-next-line unicorn/new-for-builtins
        return as(Object(BigInt(value)), index)
      case 'ArrayBuffer':
        return as(new Uint8Array(value).buffer, value)
      case 'DataView': {
        const { buffer } = new Uint8Array(value)
        return as(new DataView(buffer), value)
      }
    }
    if (typeof type === 'string' && SAFE_CONSTRUCTOR_NAMES.has(type))
      return as(new (env as any)[type](value), index)

    throw new TypeError(`unable to deserialize unsafe or unknown type: ${String(type)}`)
  }

  return unpair
}

/**
 * Returns a deserialized value from a serialized array of Records.
 * @param serialized a previously serialized value.
 */
export function deserialize(serialized: any[]): any {
  return deserializer(new Map(), serialized)(0)
}
