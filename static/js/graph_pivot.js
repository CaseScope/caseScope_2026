/*
 * Shared Relationship Graph pivot helper (Phase 0E).
 *
 * openGraphPivot(caseUuid, kind, reference) performs a read-only POST to
 * /api/graph/<case_uuid>/pivot and:
 *   - navigates to the graph deep-link when exactly one root resolves,
 *   - shows a chooser when multiple roots resolve,
 *   - shows the exact server message when nothing resolves.
 *
 * All dynamic DOM is built with createElement/textContent (no innerHTML).
 */
(function () {
  'use strict';

  function graphDeepLinkUrl(root, context) {
    var params = new URLSearchParams();
    params.set('root_entity_id', String(root.entity_id));
    var label = context && context.label ? String(context.label) : '';
    if (label) {
      params.set('pivot_context', label);
    }
    return '/case/graph?' + params.toString();
  }

  function closeModal(overlay) {
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }
  }

  function buildModal(titleText) {
    var overlay = document.createElement('div');
    overlay.className = 'modal-overlay graph-pivot-overlay';

    var container = document.createElement('div');
    container.className = 'modal-container';

    var header = document.createElement('div');
    header.className = 'modal-header';

    var title = document.createElement('h3');
    title.className = 'modal-title';
    title.textContent = titleText;

    var closeBtn = document.createElement('button');
    closeBtn.className = 'modal-close';
    closeBtn.type = 'button';
    closeBtn.textContent = '\u00d7';
    closeBtn.addEventListener('click', function () {
      closeModal(overlay);
    });

    header.appendChild(title);
    header.appendChild(closeBtn);

    var body = document.createElement('div');
    body.className = 'modal-body';

    container.appendChild(header);
    container.appendChild(body);
    overlay.appendChild(container);

    overlay.addEventListener('click', function (evt) {
      if (evt.target === overlay) {
        closeModal(overlay);
      }
    });

    return { overlay: overlay, container: container, body: body };
  }

  function showMessage(titleText, message) {
    var modal = buildModal(titleText);
    var text = document.createElement('p');
    text.className = 'graph-pivot-message';
    text.textContent = message || 'No authoritative graph object is currently materialized.';
    modal.body.appendChild(text);

    var footer = document.createElement('div');
    footer.className = 'modal-footer';
    var ok = document.createElement('button');
    ok.className = 'btn btn-secondary';
    ok.type = 'button';
    ok.textContent = 'Close';
    ok.addEventListener('click', function () {
      closeModal(modal.overlay);
    });
    footer.appendChild(ok);
    modal.container.appendChild(footer);

    document.body.appendChild(modal.overlay);
  }

  function showChooser(roots, context, message) {
    var modal = buildModal('Choose a graph root');

    if (message) {
      var note = document.createElement('p');
      note.className = 'graph-pivot-message';
      note.textContent = message;
      modal.body.appendChild(note);
    }

    var list = document.createElement('div');
    list.className = 'graph-pivot-list';

    roots.forEach(function (root) {
      var item = document.createElement('button');
      item.type = 'button';
      item.className = 'graph-pivot-item';

      var typeSpan = document.createElement('span');
      typeSpan.className = 'graph-pivot-item-type';
      typeSpan.textContent = root.entity_type || 'ENTITY';

      var valueSpan = document.createElement('span');
      valueSpan.className = 'graph-pivot-item-value';
      valueSpan.textContent = root.display_value || ('Entity #' + root.entity_id);

      item.appendChild(typeSpan);
      item.appendChild(valueSpan);
      item.addEventListener('click', function () {
        window.location.href = graphDeepLinkUrl(root, context);
      });
      list.appendChild(item);
    });

    modal.body.appendChild(list);
    document.body.appendChild(modal.overlay);
  }

  function handleResult(result) {
    var roots = (result && result.roots) || [];
    var context = (result && result.context) || {};

    if (roots.length === 1) {
      window.location.href = graphDeepLinkUrl(roots[0], context);
      return;
    }
    if (roots.length > 1) {
      showChooser(roots, context, result.ambiguous ? (result.message || 'Multiple graph roots match; select one.') : result.message);
      return;
    }
    // No roots resolved: show exact server message.
    showMessage('Open in Relationship Graph', result && result.message);
  }

  function openGraphPivot(caseUuid, kind, reference) {
    if (!caseUuid || !kind) {
      showMessage('Open in Relationship Graph', 'Missing case or pivot kind.');
      return Promise.resolve();
    }
    var url = '/api/graph/' + encodeURIComponent(caseUuid) + '/pivot';
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ kind: kind, reference: reference || {} }),
    })
      .then(function (resp) {
        return resp.json().then(function (data) {
          return { ok: resp.ok, data: data };
        });
      })
      .then(function (payload) {
        var data = payload.data || {};
        if (!payload.ok || !data.success) {
          showMessage('Open in Relationship Graph', data.error || 'Graph pivot failed.');
          return;
        }
        handleResult(data);
      })
      .catch(function () {
        showMessage('Open in Relationship Graph', 'Graph pivot request failed.');
      });
  }

  window.openGraphPivot = openGraphPivot;
})();
