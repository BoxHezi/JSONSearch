var template = "<td>$cveId</td><td>$desc</td><td>$published</td>";

function parseDesc(content) {
  return content.replace("<", "&lt;").replace(">", "&gt;").replace(/\'/g, '"');
}

function updateDisplay(data) {
  document.getElementById("result-body").innerHTML = ""; // clear the table
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
  value = value.toLowerCase();
  let filtered = []; // list to store filtered result
  for (const [k, v] of Object.entries(window.data)) {
    if (
      v.id.toLowerCase().includes(value) ||
      v.descriptions[0].value.toLowerCase().includes(value) ||
      v.published.toLowerCase().includes(value)
    ) {
      filtered.push(window.data[k]);
    }
  }
  updateDisplay(filtered);
}

function parseInputFile(e) {
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
input.addEventListener("input", parseInputFile);
