// 왼쪽 메뉴, 차트, 대화상자와 폼 동작. 외부 자산과 인라인 스크립트는 쓰지 않는다.
var sidebarCompact = window.matchMedia("(max-width: 1100px)");
var sidebarMobile = window.matchMedia("(max-width: 600px)");
var sidebarPreference = false;
try { sidebarPreference = localStorage.getItem("mint.sidebar.collapsed") === "true"; } catch (_) { /* 저장소가 꺼져도 메뉴는 동작한다. */ }
function syncSidebar() {
  document.documentElement.dataset.sidebarCollapsed = String(!sidebarMobile.matches && (sidebarCompact.matches || sidebarPreference));
}
syncSidebar();
function closeSidebar() {
  if (!document.body.classList.contains("shell")) return;
  document.body.classList.remove("menu-visible");
  document.querySelector(".sidebar-backdrop").hidden = true;
  document.querySelector("main").inert = false;
  var sidebar = document.getElementById("sidebar");
  sidebar.removeAttribute("role");
  sidebar.removeAttribute("aria-modal");
  updateSidebarButtons();
}
function updateSidebarButtons() {
  var expanded = sidebarMobile.matches ? document.body.classList.contains("menu-visible") : document.documentElement.dataset.sidebarCollapsed !== "true";
  document.querySelectorAll("[data-sidebar-toggle]").forEach(function (button) {
    button.setAttribute("aria-expanded", String(expanded));
    button.setAttribute("aria-label", expanded ? (sidebarMobile.matches ? "메뉴 닫기" : "메뉴 접기") : "메뉴 펼치기");
  });
}
function toggleSidebar() {
  if (sidebarMobile.matches) {
    var open = !document.body.classList.contains("menu-visible");
    closeSidebar();
    if (open) {
      document.body.classList.add("menu-visible");
      document.querySelector(".sidebar-backdrop").hidden = false;
      document.querySelector("main").inert = true;
      var sidebar = document.getElementById("sidebar");
      sidebar.setAttribute("role", "dialog");
      sidebar.setAttribute("aria-modal", "true");
      sidebar.querySelector("button").focus();
    } else { document.querySelector(".menu-open").focus(); }
  } else {
    sidebarPreference = document.documentElement.dataset.sidebarCollapsed !== "true";
    document.documentElement.dataset.sidebarCollapsed = String(sidebarPreference);
    try { localStorage.setItem("mint.sidebar.collapsed", String(sidebarPreference)); } catch (_) { /* 선택은 현재 화면에서 유지된다. */ }
  }
  updateSidebarButtons();
  window.dispatchEvent(new Event("resize"));
}
sidebarCompact.addEventListener("change", function () { syncSidebar(); closeSidebar(); });
sidebarMobile.addEventListener("change", function () { syncSidebar(); closeSidebar(); });
// 차트는 data-chart="{...}" 한 속성으로 그리며 kind 가 stacked · donut · bars 중 하나다.
//   stacked: {kind, labels:[], series:[{name, data:[], decision?}], previous?:[]}
//   donut:   {kind, items:[{name, value, decision?, href?}]}
//   bars:    {kind, labels:[], values:[], horizontal?:bool, links?:[]}
// 결정 값(allow·approve·block·observe)은 결정색 토큰으로, 조각을 누르면 links/href 로 이동한다.
var DECISION_TOKEN = { allow: "--ok", approve: "--wait", block: "--danger", observe: "--off" };
var PALETTE = ["--accent", "--ok", "--wait", "--danger", "--off", "--c6", "--c7", "--c8"];

function token(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}
function colorOf(decision, index) {
  return token(DECISION_TOKEN[decision] || PALETTE[index % PALETTE.length]);
}
function base() {
  return {
    textStyle: { color: token("--muted"), fontFamily: getComputedStyle(document.body).fontFamily },
    backgroundColor: "transparent",
  };
}
function axisStyle() {
  return { axisLine: { lineStyle: { color: token("--border") } }, axisLabel: { color: token("--muted") } };
}

var CHARTS = {
  stacked: function (d) {
    var series = d.series.map(function (s, i) {
      return {
        name: s.name, type: "bar", stack: "n", data: s.data,
        itemStyle: { color: colorOf(s.decision, i) },
      };
    });
    if (d.previous) {
      series.push({
        name: "이전 기간", type: "line", data: d.previous, symbol: "none",
        lineStyle: { type: "dashed", color: token("--off") }, itemStyle: { color: token("--off") },
      });
    }
    return Object.assign(base(), {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      legend: { top: 0, textStyle: { color: token("--muted") } },
      grid: { left: 40, right: 16, top: 40, bottom: 32 },
      xAxis: Object.assign({ type: "category", data: d.labels }, axisStyle()),
      yAxis: Object.assign({ type: "value", minInterval: 1 }, axisStyle()),
      series: series,
    });
  },
  donut: function (d) {
    return Object.assign(base(), {
      tooltip: { trigger: "item" },
      legend: { orient: "vertical", right: 8, top: "middle", textStyle: { color: token("--muted") } },
      series: [{
        type: "pie", center: ["32%", "50%"], radius: ["42%", "68%"], label: { show: false },
        data: d.items.map(function (it, i) {
          return { name: it.name, value: it.value, href: it.href, itemStyle: { color: colorOf(it.decision, i) } };
        }),
      }],
    });
  },
  bars: function (d) {
    var cat = Object.assign({ type: "category", data: d.labels }, axisStyle());
    var val = Object.assign({ type: "value", minInterval: 1 }, axisStyle());
    return Object.assign(base(), {
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      grid: { left: d.horizontal ? 96 : 40, right: 16, top: 16, bottom: 32 },
      xAxis: d.horizontal ? val : cat,
      yAxis: d.horizontal ? Object.assign(cat, { inverse: true }) : val,
      series: [{
        name: "건수", type: "bar", data: d.values, itemStyle: { color: token("--accent") },
      }],
    });
  },
};

// 이전 속성 형식 호환: data-chart 에 days/allowed/blocked 만 있으면 허용·차단 누적, data-bars 는 세로 막대.
function normalize(el) {
  var raw = el.hasAttribute("data-bars") ? el.getAttribute("data-bars") : el.getAttribute("data-chart");
  var d = JSON.parse(raw);
  if (el.hasAttribute("data-bars")) return Object.assign({ kind: "bars" }, d);
  if (!d.kind && d.days) {
    return {
      kind: "stacked", labels: d.days,
      series: [
        { name: "허용", data: d.allowed, decision: "allow" },
        { name: "차단", data: d.blocked, decision: "block" },
      ],
    };
  }
  return d;
}

function drawChart(el) {
  if (!window.echarts) return;
  var d = normalize(el);
  var build = CHARTS[d.kind];
  if (!build) return;
  var chart = echarts.getInstanceByDom(el) || echarts.init(el);
  chart.setOption(build(d), true);
  chart.off("click");
  chart.on("click", function (p) {
    var href = (p.data && p.data.href) || (d.links && d.links[p.dataIndex]);
    if (href) window.location.assign(href);
  });
}

function initConsole(root) {
  closeSidebar();
  root.querySelectorAll("[data-chart],[data-bars]").forEach(drawChart);
  root.querySelectorAll("input[data-confirm]").forEach(function (input) {
    var button = input.form.querySelector("button[data-needs-confirm]");
    function sync() {
      button.disabled = input.value !== input.getAttribute("data-confirm");
    }
    input.addEventListener("input", sync);
    sync();
  });
  // 시간 범위 칩: 고르면 바로 조회한다(인라인 핸들러 대신).
  root.querySelectorAll("[data-autosubmit]").forEach(function (input) {
    input.addEventListener("change", function () { input.form.requestSubmit(); });
  });
  // 행 전체 클릭: 첫 링크로 이동한다(행 안의 버튼·링크·입력을 누른 경우는 제외).
  root.querySelectorAll("table.clickable tbody tr").forEach(function (row) {
    row.addEventListener("click", function (event) {
      if (event.target.closest("a,button,input,select,textarea,label")) return;
      var link = row.querySelector("a[href]");
      if (link) link.click();
    });
  });
}
document.addEventListener("DOMContentLoaded", function () { initConsole(document); });
document.addEventListener("htmx:afterSettle", function (event) { initConsole(event.target); });
document.addEventListener("click", function (event) {
  if (event.target.closest("[data-sidebar-toggle]")) { toggleSidebar(); return; }
  if (event.target.closest("[data-sidebar-close]")) {
    closeSidebar();
    document.querySelector(".menu-open").focus();
    return;
  }
  var copy = event.target.closest("[data-copy]");
  if (copy && navigator.clipboard) {
    navigator.clipboard.writeText(copy.getAttribute("data-copy")).then(function () {
      var label = copy.textContent;
      copy.textContent = "복사됨";
      setTimeout(function () { copy.textContent = label; }, 1500);
    });
    return;
  }
  var open = event.target.closest("[data-dialog-open]");
  if (open) {
    var dialog = document.getElementById(open.getAttribute("data-dialog-open"));
    if (dialog && dialog.showModal) dialog.showModal();
  } else if (event.target.closest("[data-dialog-close]")) {
    var parent = event.target.closest("dialog");
    if (parent) parent.close();
  }
});
document.addEventListener("keydown", function (event) {
  if (document.body.classList.contains("menu-visible")) {
    if (event.key === "Escape") {
      closeSidebar();
      document.querySelector(".menu-open").focus();
      return;
    }
    if (event.key === "Tab") {
      var items = document.querySelectorAll("#sidebar button, #sidebar a");
      var first = items[0], last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  }
  if (event.key !== "Escape") return;
  var drawer = document.querySelector(".drawer[data-close]");
  if (drawer) window.location.assign(drawer.getAttribute("data-close"));
});
window.addEventListener("resize", function () {
  document.querySelectorAll("[data-chart],[data-bars]").forEach(function (el) {
    var chart = window.echarts && echarts.getInstanceByDom(el);
    if (chart) chart.resize();
  });
});
