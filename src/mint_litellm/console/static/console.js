// 차트와 이름 확인 입력만 다룬다. 외부 자산과 인라인 스크립트는 쓰지 않는다.
function initConsole(root) {
  root.querySelectorAll("[data-chart]").forEach(function (el) {
    if (!window.echarts) return;
    var data = JSON.parse(el.getAttribute("data-chart"));
    var chart = echarts.getInstanceByDom(el) || echarts.init(el);
    chart.setOption({
      color: ["#1a7f37", "#d1242f"],
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      legend: { data: ["허용", "차단"], top: 0 },
      grid: { left: 40, right: 16, top: 40, bottom: 32 },
      xAxis: { type: "category", data: data.days },
      yAxis: { type: "value", minInterval: 1 },
      series: [
        { name: "허용", type: "bar", stack: "n", data: data.allowed },
        { name: "차단", type: "bar", stack: "n", data: data.blocked },
      ],
    });
  });
  root.querySelectorAll("[data-bars]").forEach(function (el) {
    if (!window.echarts) return;
    var data = JSON.parse(el.getAttribute("data-bars"));
    var chart = echarts.getInstanceByDom(el) || echarts.init(el);
    chart.setOption({
      color: ["#0969da"],
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      grid: { left: 40, right: 16, top: 16, bottom: 32 },
      xAxis: { type: "category", data: data.labels },
      yAxis: { type: "value", minInterval: 1 },
      series: [{ name: "요청", type: "bar", data: data.values }],
    });
  });
  root.querySelectorAll("input[data-confirm]").forEach(function (input) {
    var button = input.form.querySelector("button[data-needs-confirm]");
    function sync() {
      button.disabled = input.value !== input.getAttribute("data-confirm");
    }
    input.addEventListener("input", sync);
    sync();
  });
}
document.addEventListener("DOMContentLoaded", function () { initConsole(document); });
document.addEventListener("htmx:afterSettle", function (event) { initConsole(event.target); });
window.addEventListener("resize", function () {
  document.querySelectorAll("[data-chart],[data-bars]").forEach(function (el) {
    var chart = window.echarts && echarts.getInstanceByDom(el);
    if (chart) chart.resize();
  });
});
