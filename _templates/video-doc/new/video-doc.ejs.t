---
to: docs/videos/<%= category %>/<%= num %>-<%= name %>/index.md
sh: cat tmp/<%= tmp %> >> docs/videos/<%= category %>/<%= num %>-<%= name %>/index.md
---
---
id: <%= name %>
title: <%= title %>
slug: ../<%= name %>
description: 请输入描述
keywords:
  - <%= category %>
  - color
  - grid
  - place-items
  - 前端
  - frontend
---

import BVideo from "@site/src/components/BVideo";

<BVideo src="<%- url %>"/>
