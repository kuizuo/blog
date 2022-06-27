"use strict";
/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getVersionTags = void 0;
const utils_1 = require("@docusaurus/utils");
const lodash_1 = __importDefault(require("lodash"));
function getVersionTags(docs) {
    const groups = (0, utils_1.groupTaggedItems)(docs, (doc) => doc.tags);
    return lodash_1.default.mapValues(groups, (group) => ({
        label: group.tag.label,
        docIds: group.items.map((item) => item.id),
        permalink: group.tag.permalink,
    }));
}
exports.getVersionTags = getVersionTags;
