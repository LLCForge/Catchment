(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var svg = document.getElementById("map");
  var legend = document.getElementById("legend");
  if (!svg || !window.d3 || !window.topojson) return;
  var data = JSON.parse(document.getElementById("catchment-data").textContent);
  var world = JSON.parse(document.getElementById("catchment-world").textContent);
  // Colour-blind friendly categorical palette; "unattributed" is always grey.
  var palette = ["#0072b2", "#e69f00", "#009e73", "#d55e00", "#cc79a7", "#56b4e9", "#f0e442", "#8c564b"];
  var colors = {};
  var next = 0;
  data.pops.forEach(function (p) {
    colors[p] = p === "unattributed" ? "#8b949e" : palette[next++ % palette.length];
  });
  function el(name, attrs) {
    var e = document.createElementNS(NS, name);
    Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }
  var projection = d3.geoNaturalEarth1().fitSize([960, 500], { type: "Sphere" });
  var path = d3.geoPath(projection);
  svg.appendChild(el("path", { d: path({ type: "Sphere" }), class: "sphere" }));
  var g = el("g", { class: "countries" });
  topojson.feature(world, world.objects.countries).features.forEach(function (f) {
    var d = path(f);
    if (d) g.appendChild(el("path", { d: d }));
  });
  svg.appendChild(g);
  data.points.forEach(function (p) {
    var xy = projection([p.lon, p.lat]);
    if (!xy || !isFinite(xy[0]) || !isFinite(xy[1])) return;
    var c = el("circle", { cx: xy[0].toFixed(1), cy: xy[1].toFixed(1), r: 4, fill: colors[p.pop] || "#8b949e", class: "pt" });
    var t = document.createElementNS(NS, "title");
    t.textContent = p.vantage + " (" + (p.country || "??") + ") -> " + p.pop +
      (p.rtt === null || p.rtt === undefined ? "" : ", " + p.rtt.toFixed(1) + " ms");
    c.appendChild(t);
    svg.appendChild(c);
  });
  data.pops.forEach(function (p) {
    var li = document.createElement("li");
    var sw = el("svg", { width: 12, height: 12, "aria-hidden": "true" });
    sw.appendChild(el("circle", { cx: 6, cy: 6, r: 5, fill: colors[p] }));
    li.appendChild(sw);
    li.appendChild(document.createTextNode(p));
    legend.appendChild(li);
  });
})();
