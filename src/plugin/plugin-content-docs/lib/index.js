"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const docsPluginExports = __importStar(require("@docusaurus/plugin-content-docs"));
const tags_1 = require("./tags");
const docsPlugin = docsPluginExports.default;
function docsPluginEnhanced(context, options) {
    return __awaiter(this, void 0, void 0, function* () {
        const docsPluginInstance = yield docsPlugin(context, options);
        return {
            name: 'docusaurus-plugin-content-docs-enhanced',
            loadContent() {
                return __awaiter(this, void 0, void 0, function* () {
                    return yield docsPluginInstance.loadContent();
                });
            },
            contentLoaded({ content, actions }) {
                return __awaiter(this, void 0, void 0, function* () {
                    // Create default plugin pages
                    // await docsPluginInstance.contentLoaded({ content, actions })
                    // Create your additional pages
                    const { loadedVersions } = content;
                    const { setGlobalData } = actions;
                    const versionTags = (0, tags_1.getVersionTags)(loadedVersions[0].docs);
                    const tagsProp = Object.values(versionTags).map((tagValue) => ({
                        label: tagValue.label,
                        permalink: tagValue.permalink,
                        count: tagValue.docIds.length,
                    }));
                    if (tagsProp.length > 0) {
                        setGlobalData({
                            tags: tagsProp,
                        });
                    }
                });
            },
        };
    });
}
module.exports = Object.assign(Object.assign({}, docsPluginExports), { default: docsPluginEnhanced });
