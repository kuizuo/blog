---
name: kuizuo
description: Use when working with Kuizuo / 愧怍 personal source material, including drafting or refining a Kuizuo Agent Skill, writing bios or introductions based on collected references, answering questions about Kuizuo from the local source archive, or extracting facts from Kuizuo's blog, projects, experiences, and public feedback. Load the bundled references before making claims.
---

# Kuizuo Source Material

Use this skill to work from collected source material about Kuizuo / 愧怍.

## Workflow

1. Identify the requested output: source organization, bio, profile, timeline, project list, Agent Skill draft, or factual Q&A.
2. Load only the relevant reference files:
   - `references/个人内容.md` for self-introduction, personal statements, interests, skills, values, and writing habits.
   - `references/经历与事件.md` for timeline material, education, work, legal/administrative events, travel, relationships, and life records.
   - `references/他人评价与外部引用.md` for comments, external listings, and citations by third parties.
3. Preserve source labels when presenting facts. Distinguish `本人原话`, `本人文章`, `公开资料`, `他人评价`, `外部收录`, and `外部引用`.
4. Do not treat third-party comments as verified facts about Kuizuo. Use them only as comments or reception unless the user asks for opinion material.
5. Do not invent missing facts. If a requested aspect is not covered, state that the reference set does not contain enough source material.

## Output Rules

- For factual extraction, quote or paraphrase only from loaded references and keep source links attached.
- For skill drafting, keep `SKILL.md` concise and move detailed facts into `references/` instead of duplicating them in the skill body.
- For any analysis or distillation, separate original source records from interpretation unless the user explicitly asks for only raw organization.
