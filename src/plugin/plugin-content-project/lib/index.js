"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const project_1 = require("../../../data/project");
function generateProjects(projectsPath) {
    return project_1.sortedProjects;
}
function projectPlugin(context, options) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        return {
            name: 'docusaurus-plugin-content-project',
            loadContent() {
                return tslib_1.__awaiter(this, void 0, void 0, function* () {
                    const projects = yield generateProjects();
                    return { projects };
                });
            },
            contentLoaded({ content, actions }) {
                return tslib_1.__awaiter(this, void 0, void 0, function* () {
                    const { projects } = content;
                    const { setGlobalData } = actions;
                    setGlobalData({
                        projects: projects,
                    });
                });
            },
        };
    });
}
exports.default = projectPlugin;
