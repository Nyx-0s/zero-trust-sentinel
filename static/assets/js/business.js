// ===== Business intelligence (founder-skill integration) ====================
// Talks to the same API_BASE as the scan flow. No secrets ship here: the
// browser only ever sees skill ids, statuses and the documents it requests.
(function () {
    'use strict';

    var KIND_LABEL = {
        tool:     { t: 'Deterministic',  c: '#15803d' },
        llm:      { t: 'AI-generated',   c: '#b45309' },
        research: { t: 'Research gate',  c: '#b91c1c' }
    };
    var STATUS_LABEL = {
        pending: 'not run yet', running: 'running…', complete: 'complete',
        failed: 'failed', needs_research: 'needs sources'
    };

    var state = { projects: [], skills: [], project: null, outputs: [], timer: null };
    var $ = function (id) { return document.getElementById(id); };

    function showError(msg) {
        var el = $('biz-error');
        if (!msg) { el.style.display = 'none'; el.textContent = ''; return; }
        el.style.display = 'block';
        el.textContent = msg;
    }

    function badge(kind) {
        var k = KIND_LABEL[kind] || { t: kind, c: '#475569' };
        return '<span class="pill" style="border-color:' + k.c + ';color:' + k.c + ';">' + k.t + '</span>';
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>');
    }

    // ---- API helpers -------------------------------------------------------
    async function api(path, opts) {
        var res = await fetch(API_BASE + path, Object.assign({
            headers: { 'Content-Type': 'application/json' }
        }, opts || {}));
        var body = null;
        try { body = await res.json(); } catch (e) { body = null; }
        if (!res.ok) {
            var detail = body && (body.error || body.detail);
            throw new Error(detail || (path + ' failed with HTTP ' + res.status));
        }
        return body;
    }

    // ---- Projects ----------------------------------------------------------
    async function loadProjects() {
        try {
            var body = await api('/business/projects');
            // The endpoint returns {projects: [...]}; older cached pages may
            // receive a bare array, so accept both shapes.
            state.projects = Array.isArray(body) ? body : (body.projects || []);
            renderProjects();
        } catch (e) {
            showError('Could not load business projects: ' + e.message);
        } finally {
            $('biz-loading').style.display = 'none';
            $('biz-projects-wrap').style.display = 'block';
        }
    }

    function renderProjects() {
        var box = $('biz-projects');
        if (!state.projects.length) {
            box.innerHTML = '<p class="small muted">No projects yet. Create one — the ' +
                'Sentinel template prefills a real product context from this repository.</p>';
            return;
        }
        box.innerHTML = state.projects.map(function (p) {
            var active = state.project && state.project.id === p.id;
            return '<button class="btn ' + (active ? 'btn-primary' : 'btn-ghost') + '" ' +
                'onclick="window.bizSelect(' + p.id + ')">' + esc(p.name) +
                '<span class="small"> · ' + (p.complete || 0) + '/11 done' +
                (p.failed ? ' · ' + p.failed + ' failed' : '') + '</span></button>';
        }).join('');
    }

    async function createProject(name, useTemplate) {
        var context = {};
        if (useTemplate) {
            try { context = await api('/business/context-template'); }
            catch (e) { showError('Template unavailable: ' + e.message); return; }
        }
        try {
            var created = await api('/business/projects', {
                method: 'POST',
                body: JSON.stringify({ name: name, context: context })
            });
            await loadProjects();
            await selectProject(created.id);
        } catch (e) { showError('Could not create project: ' + e.message); }
    }

    window.bizCreate = function () {
        var name = $('biz-new-name').value.trim();
        if (!name) { showError('Give the project a name first.'); return; }
        showError('');
        createProject(name, false);
    };

    window.bizCreateFromTemplate = function () {
        var name = $('biz-new-name').value.trim() || 'Zero-Trust Sentinel plan';
        showError('');
        createProject(name, true);
    };

    window.bizSelect = function (id) { selectProject(id); };

    async function selectProject(id) {
        try {
            state.project = await api('/business/projects/' + id);
            $('biz-workspace').style.display = 'block';
            $('biz-project-title').textContent = state.project.name;
            $('biz-context').value = JSON.stringify(state.project.context || {}, null, 2);
            $('biz-status').textContent = 'Pick a skill to run it on its own.';
            $('biz-output-wrap').style.display = 'none';
            renderProjects();
            await refreshOutputs();
            await loadSkills();
        } catch (e) { showError('Could not open project: ' + e.message); }
    }

    async function refreshOutputs() {
        if (!state.project) return;
        try {
            var full = await api('/business/projects/' + state.project.id);
            state.project = full;
            state.outputs = full.outputs || [];
            renderSkills();
            maybePoll();
        } catch (e) { showError('Could not load progress: ' + e.message); }
    }

    function maybePoll() {
        var running = state.outputs.some(function (o) { return o.status === 'running'; });
        if (running && !state.timer) {
            state.timer = setInterval(async function () {
                await refreshOutputs();
                if (!state.outputs.some(function (o) { return o.status === 'running'; })) {
                    clearInterval(state.timer); state.timer = null;
                }
            }, 2500);
        }
    }

    // ---- Skills ------------------------------------------------------------
    async function loadSkills() {
        if (state.skills.length) return;
        try {
            var body = await api('/business/skills');
            state.skills = Array.isArray(body) ? body : (body.skills || []);
            renderSkills();
        } catch (e) { showError('Could not load skills: ' + e.message); }
    }

    function outputFor(skillId) {
        return state.outputs.filter(function (o) { return o.skill_id === skillId; })[0];
    }

    function renderSkills() {
        if (!state.skills.length) return;
        $('biz-skills').innerHTML = state.skills.map(function (s) {
            var o = outputFor(s.id);
            var status = o ? (STATUS_LABEL[o.status] || o.status) : 'not run yet';
            var color = o ? ({ complete: '#15803d', failed: '#b91c1c',
                running: '#b45309', needs_research: '#b91c1c' }[o.status] || '#475569')
                : '#94a3b8';
            var canOpen = o && (o.status === 'complete' || o.status === 'failed' ||
                                o.status === 'needs_research');
            return '<div class="card" style="padding:.7rem;margin:0;">' +
                '<div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;">' +
                badge(s.kind) +
                '<strong style="flex:1;">' + esc(s.title) + '</strong>' +
                '<button class="btn btn-secondary" ' +
                (o && o.status === 'running' ? 'disabled' : '') +
                ' onclick="window.bizRun(\'' + s.id + '\')">Run</button>' +
                (canOpen ? '<button class="btn btn-ghost" onclick="window.bizOpen(\'' + s.id + '\')">Open</button>' : '') +
                '</div>' +
                '<p class="small muted" style="margin:.4rem 0 0;">' + esc(s.summary) +
                ' <span style="color:' + color + ';">· ' + esc(status) + '</span>' +
                (o && o.error ? ' · ' + esc(String(o.error).slice(0, 160)) : '') +
                '</p></div>';
        }).join('');
    }

    async function runSkill(skillId) {
        if (!state.project) { showError('Select or create a project first.'); return; }
        showError('');
        $('biz-status').textContent = 'Starting ' + skillId + '…';
        try {
            await api('/business/projects/' + state.project.id + '/run', {
                method: 'POST',
                body: JSON.stringify({ skill_id: skillId })
            });
            await refreshOutputs();
        } catch (e) { showError('Could not start skill: ' + e.message); }
    }

    window.bizRun = runSkill;

    window.bizRunWorkflow = async function () {
        if (!state.project) { showError('Select or create a project first.'); return; }
        showError('');
        $('biz-status').textContent = 'Workflow started: 11 skills in order…';
        try {
            await api('/business/projects/' + state.project.id + '/run', {
                method: 'POST', body: JSON.stringify({ skill_id: 'workflow' })
            });
            await refreshOutputs();
        } catch (e) { showError('Could not start workflow: ' + e.message); }
    };

    window.bizSaveContext = async function () {
        if (!state.project) return;
        showError('');
        var parsed;
        try { parsed = JSON.parse($('biz-context').value); }
        catch (e) { showError('Context must be valid JSON: ' + e.message); return; }
        try {
            state.project = await api('/business/projects/' + state.project.id + '/context', {
                method: 'POST', body: JSON.stringify({ context: parsed })
            });
            $('biz-status').textContent = 'Context saved.';
        } catch (e) { showError('Could not save context: ' + e.message); }
    };

    // ---- Outputs -----------------------------------------------------------
    window.bizOpen = async function (skillId) {
        if (!state.project) return;
        showError('');
        try {
            var out = await api('/business/projects/' + state.project.id +
                '/outputs/' + encodeURIComponent(skillId));
            $('biz-output-wrap').style.display = 'block';
            $('biz-output-title').textContent = out.skill_id;
            var kind = KIND_LABEL[out.kind] || { t: out.kind };
            var meta = [kind.t];
            if (out.meta && out.meta.model) meta.push('model ' + out.meta.model);
            if (out.meta && out.meta.verdict) meta.push('verdict: ' + out.meta.verdict);
            if (out.meta && out.meta.assumptions) meta.push(out.meta.assumptions);
            if (out.meta && out.meta.evidence_status === 'missing') {
                meta.push('no sources supplied');
            }
            if (out.updated_at) meta.push('updated ' + out.updated_at);
            $('biz-output-meta').textContent = meta.join(' · ');
            $('biz-output').textContent = out.status === 'complete'
                ? (out.content || '(empty document)')
                : ((out.status === 'failed' || out.status === 'needs_research')
                    ? 'Not produced — ' + (out.error || 'no detail recorded')
                    : 'Status: ' + out.status);
        } catch (e) { showError('Could not load output: ' + e.message); }
    };

    window.bizRerun = function () {
        var id = $('biz-output-title').textContent;
        if (id) runSkill(id);
    };

    window.bizDownload = function () {
        var id = $('biz-output-title').textContent || 'output';
        var blob = new Blob([$('biz-output').textContent], { type: 'text/markdown' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = id + '.md';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    };

    // ---- Boot --------------------------------------------------------------
    document.addEventListener('DOMContentLoaded', function () {
        if (!$('biz-projects')) return;   // page without the section
        loadProjects();
    });
})();
