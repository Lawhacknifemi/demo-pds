import { CID } from 'multiformats';
import * as dagCbor from '@ipld/dag-cbor';

/**
 * concepts:
 * 
 * "record" object is JavaScript object representation of a dag_cbor blob.
 * CIDs are represented with the CID class.
 * 
 * a "json" object is also a JavaScript object representation, but CIDs are referenced as {"$link": ...}
 * (and non-json-representable types, like bytes, are forbidden)
 * 
 * There are probably some fun round-trip breakage bugs relating to $link
 */

/**
 * Convert a record to JSON format
 * @param {Object} record - The record to convert
 * @returns {Object} - JSON representation of the record
 */
export function recordToJson(record) {
    if (record === null || record === undefined) {
        return null;
    }
    if (Array.isArray(record)) {
        return record.map(recordToJson);
    }
    if (record instanceof CID) {
        return { $link: record.toString('base32') };
    }
    if (record instanceof Uint8Array) {
        return { $bytes: Buffer.from(record).toString('base64') };
    }
    if (typeof record === 'object') {
        const result = {};
        for (const [key, value] of Object.entries(record)) {
            if (value !== undefined) {
                result[key] = recordToJson(value);
            }
        }
        return result;
    }
    return record;
}

/**
 * Find all CID references in a record
 * @param {Object} record - The record to search
 * @returns {Generator<CID>} - Generator yielding all CIDs found
 */
export function* enumerateRecordCids(record) {
    if (record === null || record === undefined) {
        return;
    }
    if (Array.isArray(record)) {
        for (const item of record) {
            yield* enumerateRecordCids(item);
        }
    } else if (record instanceof CID) {
        yield record;
    } else if (typeof record === 'object') {
        for (const value of Object.values(record)) {
            yield* enumerateRecordCids(value);
        }
    }
}

/**
 * Convert JSON back to record format
 * @param {Object} data - The JSON data to convert
 * @returns {Object} - Record representation
 */
export function jsonToRecord(json) {
    if (json === null || json === undefined) {
        return null;
    }
    if (Array.isArray(json)) {
        return json.map(jsonToRecord);
    }
    if (typeof json === 'object') {
        if ('$link' in json) {
            return CID.parse(json.$link);
        }
        if ('$bytes' in json) {
            return Buffer.from(json.$bytes, 'base64');
        }
        const result = {};
        for (const [key, value] of Object.entries(json)) {
            if (value !== undefined) {
                result[key] = jsonToRecord(value);
            }
        }
        return result;
    }
    return json;
} 