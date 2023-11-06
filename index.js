var template = "<td>$cveId</td><td>$desc</td><td>$published</td>";

function init() {}

function parseDesc(content) {
  return content.replace("<", "&lt;").replace(">", "&gt;").replace(/\'/g, '"');
}

function updateDisplay(data) {
  const cves = data.cve;
  for (const [k, v] of Object.entries(cves)) {
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

function search() {}

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
    // console.log(typeof result);
    // console.log(result);
    window.data = result;
    updateDisplay(result);
    return result;
  };
}

input = document.querySelector("input");
input.addEventListener("input", inputFunc);

// function inputTest(e) {
//   console.log(e);
//   console.log("TEST");
// }
