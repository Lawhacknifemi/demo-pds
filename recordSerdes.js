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
function recordToJson(record) {
    if (Array.isArray(record)) {
        return record.map(r => recordToJson(r));
    }
    if (record && typeof record === 'object') {
        if (record instanceof CID) {
            return { "$link": record.toString() };
        }
        if (record instanceof Uint8Array) {
            throw new TypeError("can't represent bytes as JSON");
        }
        return Object.fromEntries(
            Object.entries(record).map(([k, v]) => [k, recordToJson(v)])
        );
    }
    return record;
}

/**
 * Find all CID references in a record
 * @param {Object} record - The record to search
 * @returns {Generator<CID>} - Generator yielding all CIDs found
 */
function* enumerateRecordCids(record) {
    if (Array.isArray(record)) {
        for (const r of record) {
            yield* enumerateRecordCids(r);
        }
    }
    if (record && typeof record === 'object') {
        if (record instanceof CID) {
            yield record;
            return;
        }
        for (const r of Object.values(record)) {
            yield* enumerateRecordCids(r);
        }
    }
}

/**
 * Convert JSON back to record format
 * @param {Object} data - The JSON data to convert
 * @returns {Object} - Record representation
 */
function jsonToRecord(data) {
    if (Array.isArray(data)) {
        return data.map(r => jsonToRecord(r));
    }
    if (data && typeof data === 'object') {
        if (Object.keys(data).length === 1 && '$link' in data) {
            return CID.parse(data.$link);
        }
        return Object.fromEntries(
            Object.entries(data).map(([k, v]) => [k, jsonToRecord(v)])
        );
    }
    return data;
}

// Export all required functions
export { recordToJson, jsonToRecord, enumerateRecordCids }; 