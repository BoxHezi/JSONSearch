var template = "<td>$cveId</td><td>$desc</td><td>$published</td>";

function init() {}

function parseDesc(content) {
  return content.replace("<", "&lt;").replace(">", "&gt;").replace(/\'/g, '"');
}

function updateDisplay(data) {
  document.getElementById("result-body").innerHTML = "";
  for (const [k, v] of Object.entries(data)) {
    let tr = document.createElement("tr");
    let content = template
      .replace("$cveId", v.id)
      .replace("$desc", parseDesc(v.descriptions[0].value))
      .replace("$published", v.published.replace("T", " "));
    tr.innerHTML = content;
    let tbodyContent = document.getElementById("result-body");
    tbodyContent.appendChild(tr);
  }
}

function search(value) {
  let filtered = [];
  for (const [k, v] of Object.entries(window.data)) {
    if (
      v.id.includes(value) ||
      v.descriptions[0].value.includes(value) ||
      v.published.includes(value)
    ) {
      filtered.push(window.data[k]);
    }
  }
  updateDisplay(filtered);
}

function inputFunc(e) {
  const file = e.target.files[0];
  const reader = new FileReader();
  reader.readAsText(file);
  reader.onloadend = function (e) {
    let result = e.target.result;
    try {
      result = JSON.parse(result);
    } catch (err) {
      console.log(err);
    }
    window.data = result.cve;
    updateDisplay(window.data);
  };
}

input = document.querySelector("input");
input.addEventListener("input", inputFunc);

// function inputTest(e) {
//   console.log(e);
//   console.log("TEST");
// }
