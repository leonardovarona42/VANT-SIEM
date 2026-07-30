/**
 * VANT-SIEM Table Features
 * - Column visibility toggle
 * - Column resize by drag
 * - Time range filter
 * - Field value include/exclude (+/-) filtering
 */
(function () {
    "use strict";

    function initTableFeatures(tableId, opts) {
        opts = opts || {};
        var root = document.getElementById(tableId);
        if (!root) return;
        var table = root.querySelector("table");
        if (!table) return;
        var tbody = table.querySelector("tbody");
        var thead = table.querySelector("thead");
        var headers = thead ? thead.querySelectorAll("th") : [];

        // ── State ────────────────────────────────────────────────
        var state = {
            hiddenCols: {},
            colWidths: {},
            filters: [],
            timeStart: opts.timeStart || "",
            timeEnd: opts.timeEnd || "",
            timeField: opts.timeField || "fecha",
        };

        // ── Build toolbar ────────────────────────────────────────
        var toolbar = document.createElement("div");
        toolbar.className = "flex flex-wrap items-center gap-2 mb-3";
        root.insertBefore(toolbar, root.firstChild);

        // Time range
        var timeWrap = document.createElement("div");
        timeWrap.className = "flex items-center gap-2";
        timeWrap.innerHTML =
            '<label class="text-xs font-medium dark:text-surface-300 text-surface-600">Desde:</label>' +
            '<input type="date" id="' + tableId + '-date-start" class="px-2 py-1 text-xs bg-white dark:bg-surface-800 border dark:border-surface-700 border-surface-300 rounded-lg dark:text-surface-200 text-surface-800 focus:ring-2 focus:ring-brand-500 outline-none">' +
            '<label class="text-xs font-medium dark:text-surface-300 text-surface-600">Hasta:</label>' +
            '<input type="date" id="' + tableId + '-date-end" class="px-2 py-1 text-xs bg-white dark:bg-surface-800 border dark:border-surface-700 border-surface-300 rounded-lg dark:text-surface-200 text-surface-800 focus:ring-2 focus:ring-brand-500 outline-none">' +
            '<button id="' + tableId + '-date-apply" class="px-2 py-1 text-xs font-medium text-white bg-brand-600 hover:bg-brand-700 rounded-lg transition-colors">Filtrar</button>' +
            '<button id="' + tableId + '-date-clear" class="px-2 py-1 text-xs font-medium text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 transition-colors">Limpiar</button>';
        toolbar.appendChild(timeWrap);

        if (opts.timeStart) {
            timeWrap.querySelector("input[type=date]").value = opts.timeStart;
        }
        if (opts.timeEnd) {
            timeWrap.querySelectorAll("input[type=date]")[1].value = opts.timeEnd;
        }

        // Column visibility dropdown
        var colDrop = document.createElement("div");
        colDrop.className = "relative";
        colDrop.innerHTML =
            '<button id="' + tableId + '-col-btn" class="px-2 py-1 text-xs font-medium dark:text-surface-300 text-surface-600 border dark:border-surface-700 border-surface-300 rounded-lg hover:dark:bg-surface-700 hover:bg-surface-100 transition-colors">' +
            '<i class="fas fa-columns mr-1"></i>Columnas</button>' +
            '<div id="' + tableId + '-col-menu" class="hidden absolute right-0 mt-1 w-56 bg-white dark:bg-surface-800 border dark:border-surface-700 border-surface-300 rounded-lg shadow-xl z-50 max-h-64 overflow-y-auto"></div>';
        toolbar.appendChild(colDrop);

        var colMenu = colDrop.querySelector("#" + tableId + "-col-menu");
        headers.forEach(function (th, idx) {
            var label = th.textContent.trim() || "Col " + (idx + 1);
            var item = document.createElement("label");
            item.className = "flex items-center gap-2 px-3 py-1.5 text-xs dark:text-surface-300 text-surface-600 hover:dark:bg-surface-700 hover:bg-surface-100 cursor-pointer";
            item.innerHTML =
                '<input type="checkbox" checked data-col-idx="' + idx + '" class="rounded border-surface-300 dark:border-surface-600 text-brand-600 focus:ring-brand-500">' +
                '<span>' + label + '</span>';
            colMenu.appendChild(item);
        });

        // Active filters display
        var filterBar = document.createElement("div");
        filterBar.id = tableId + "-filters";
        filterBar.className = "flex flex-wrap gap-1.5 mb-2";
        toolbar.parentNode.insertBefore(filterBar, toolbar.nextSibling);

        // ── Event handlers ───────────────────────────────────────

        // Column visibility toggle
        document.getElementById(tableId + "-col-btn").addEventListener("click", function (e) {
            e.stopPropagation();
            colMenu.classList.toggle("hidden");
        });
        document.addEventListener("click", function () {
            colMenu.classList.add("hidden");
        });
        colMenu.addEventListener("click", function (e) {
            e.stopPropagation();
        });

        colMenu.querySelectorAll("input[type=checkbox]").forEach(function (cb) {
            cb.addEventListener("change", function () {
                var idx = parseInt(this.getAttribute("data-col-idx"));
                state.hiddenCols[idx] = !this.checked;
                applyVisibility();
            });
        });

        function applyVisibility() {
            headers.forEach(function (th, idx) {
                var display = state.hiddenCols[idx] ? "none" : "";
                th.style.display = display;
                var rows = tbody.querySelectorAll("tr");
                rows.forEach(function (row) {
                    var cell = row.cells[idx];
                    if (cell) cell.style.display = display;
                });
            });
        }

        // Time range filter
        document.getElementById(tableId + "-date-apply").addEventListener("click", function () {
            var start = document.getElementById(tableId + "-date-start").value;
            var end = document.getElementById(tableId + "-date-end").value;
            state.timeStart = start;
            state.timeEnd = end;
            applyTimeFilter();
        });
        document.getElementById(tableId + "-date-clear").addEventListener("click", function () {
            document.getElementById(tableId + "-date-start").value = "";
            document.getElementById(tableId + "-date-end").value = "";
            state.timeStart = "";
            state.timeEnd = "";
            applyTimeFilter();
        });

        function applyTimeFilter() {
            var rows = tbody.querySelectorAll("tr");
            var timeColIdx = findTimeColumn();
            rows.forEach(function (row) {
                if (timeColIdx === -1) return;
                var cell = row.cells[timeColIdx];
                if (!cell) return;
                var val = cell.getAttribute("data-sort") || cell.textContent.trim();
                var show = true;
                if (state.timeStart && val < state.timeStart) show = false;
                if (state.timeEnd && val > state.timeEnd + "T23:59:59") show = false;
                row.style.display = show ? "" : "none";
            });
            renderFilterChips();
        }

        function findTimeColumn() {
            for (var i = 0; i < headers.length; i++) {
                var text = headers[i].textContent.toLowerCase();
                if (text.indexOf("fecha") !== -1 || text.indexOf("date") !== -1 || text.indexOf("time") !== -1) return i;
            }
            return -1;
        }

        // Field value +/- filtering
        tbody.addEventListener("mouseover", function (e) {
            var td = e.target.closest("td");
            if (!td || td.querySelector(".field-filter-btns")) return;
            var row = td.closest("tr");
            if (!row || row.querySelector("td[colspan]")) return;
            var val = (td.getAttribute("data-filter") || td.textContent || "").trim();
            if (!val || val.length > 60 || val === "-" || val === "0") return;

            var btns = document.createElement("span");
            btns.className = "field-filter-btns inline-flex gap-0.5 ml-1";
            btns.innerHTML =
                '<button title="Solo este valor" class="field-include w-4 h-4 rounded bg-emerald-600/80 hover:bg-emerald-500 text-white text-[9px] font-bold leading-none flex items-center justify-center transition-colors">+</button>' +
                '<button title="Excluir este valor" class="field-exclude w-4 h-4 rounded bg-red-600/80 hover:bg-red-500 text-white text-[9px] font-bold leading-none flex items-center justify-center transition-colors">-</button>';
            td.appendChild(btns);
        });

        tbody.addEventListener("mouseout", function (e) {
            var td = e.target.closest("td");
            if (!td) return;
            var related = e.relatedTarget;
            if (related && td.contains(related)) return;
            var btns = td.querySelector(".field-filter-btns");
            if (btns) btns.remove();
        });

        tbody.addEventListener("click", function (e) {
            var btn = e.target.closest(".field-include, .field-exclude");
            if (!btn) return;
            var td = btn.closest("td");
            var row = btn.closest("tr");
            var colIdx = Array.prototype.indexOf.call(row.cells, td);
            var val = (td.getAttribute("data-filter") || td.textContent || "").trim();
            var header = headers[colIdx] ? headers[colIdx].textContent.trim() : "Col " + (colIdx + 1);
            var mode = btn.classList.contains("field-include") ? "include" : "exclude";

            // Check if same filter exists, toggle off
            var existing = state.filters.findIndex(function (f) {
                return f.col === colIdx && f.val === val && f.mode === mode;
            });
            if (existing !== -1) {
                state.filters.splice(existing, 1);
            } else {
                // If include, remove any other include on same column
                if (mode === "include") {
                    state.filters = state.filters.filter(function (f) {
                        return !(f.col === colIdx && f.mode === "include");
                    });
                }
                state.filters.push({ col: colIdx, val: val, mode: mode, header: header });
            }
            applyFieldFilters();
            renderFilterChips();
        });

        function applyFieldFilters() {
            var rows = tbody.querySelectorAll("tr");
            rows.forEach(function (row) {
                var show = true;
                state.filters.forEach(function (f) {
                    var cell = row.cells[f.col];
                    if (!cell) return;
                    var cellVal = (cell.getAttribute("data-filter") || cell.textContent || "").trim();
                    if (f.mode === "include" && cellVal !== f.val) show = false;
                    if (f.mode === "exclude" && cellVal === f.val) show = false;
                });
                row.style.display = show ? "" : "none";
            });
        }

        function renderFilterChips() {
            filterBar.innerHTML = "";
            state.filters.forEach(function (f, i) {
                var color = f.mode === "include" ? "bg-emerald-600" : "bg-red-600";
                var prefix = f.mode === "include" ? "=" : "!=";
                var chip = document.createElement("span");
                chip.className = color + " text-white text-[10px] px-2 py-0.5 rounded-full flex items-center gap-1";
                chip.innerHTML = f.header + " " + prefix + " " + f.val +
                    ' <button class="ml-0.5 hover:text-surface-200 font-bold">&times;</button>';
                chip.querySelector("button").addEventListener("click", function () {
                    state.filters.splice(i, 1);
                    applyFieldFilters();
                    renderFilterChips();
                });
                filterBar.appendChild(chip);
            });
            if (state.timeStart || state.timeEnd) {
                var tchip = document.createElement("span");
                tchip.className = "bg-brand-600 text-white text-[10px] px-2 py-0.5 rounded-full flex items-center gap-1";
                tchip.innerHTML = "Fecha: " + (state.timeStart || "*") + " a " + (state.timeEnd || "*") +
                    ' <button class="ml-0.5 hover:text-surface-200 font-bold">&times;</button>';
                tchip.querySelector("button").addEventListener("click", function () {
                    document.getElementById(tableId + "-date-start").value = "";
                    document.getElementById(tableId + "-date-end").value = "";
                    state.timeStart = "";
                    state.timeEnd = "";
                    applyTimeFilter();
                });
                filterBar.appendChild(tchip);
            }
        }

        // ── Column resize ────────────────────────────────────────
        headers.forEach(function (th, idx) {
            th.style.position = "relative";
            th.style.userSelect = "none";
            var handle = document.createElement("div");
            handle.className = "col-resize-handle";
            handle.style.cssText =
                "position:absolute;right:0;top:0;bottom:0;width:4px;cursor:col-resize;z-index:10;" +
                "background:transparent;transition:background 0.2s;";
            th.appendChild(handle);

            handle.addEventListener("mouseenter", function () {
                handle.style.background = "rgba(99,102,241,0.5)";
            });
            handle.addEventListener("mouseleave", function () {
                if (!handle._dragging) handle.style.background = "transparent";
            });

            var startX, startW;
            handle.addEventListener("mousedown", function (e) {
                e.preventDefault();
                handle._dragging = true;
                startX = e.clientX;
                startW = th.offsetWidth;
                document.body.style.cursor = "col-resize";

                function onMove(ev) {
                    var diff = ev.clientX - startX;
                    var newW = Math.max(40, startW + diff);
                    th.style.width = newW + "px";
                    th.style.minWidth = newW + "px";
                }
                function onUp() {
                    handle._dragging = false;
                    handle.style.background = "transparent";
                    document.body.style.cursor = "";
                    document.removeEventListener("mousemove", onMove);
                    document.removeEventListener("mouseup", onUp);
                }
                document.addEventListener("mousemove", onMove);
                document.addEventListener("mouseup", onUp);
            });
        });
    }

    // Expose globally
    window.VANTTable = { init: initTableFeatures };
})();
