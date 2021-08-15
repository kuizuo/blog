---
inject: true
to: sidebars.js
before: "(?<=<%= sidebar %>[\"]?: \\[[^\\]]+)\\],"
skip_if: "videos/<%= category %>/<%= name %>/<%= name %>"
---
      "videos/<%= category %>/<%= name %>/<%= name %>",