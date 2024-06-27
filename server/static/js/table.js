const flags_table = document.getElementById("flags");
const next_page_btn = document.getElementById("next-page");
const prev_page_btn = document.getElementById("prev-page");
const page_counter = document.getElementById("page-counter");
const entries_count = document.getElementById("count");

let page = 0, rows = parseInt(entries_count.value);

function zero_pad(n, k) {
    let s = `${k}`;
    while (s.length < n) {
        s = "0" + s;
    }
    return s;
}

function change_page(delta) {
    if (page + delta < 0) {
        console.log(page);
        return;
    }
    page += delta;
    refresh_tables();
    page_counter.textContent = `Page ${zero_pad(2, page+1)}`
}

function build_table_header(headers) {
    let html = "<thead><tr>";
    headers.forEach(h => html += `<th class="${h.toLowerCase().replaceAll(' ', '-')}">${h}</th>`);
    html += "</tr></thead>";
    return html;
}

function build_table_rows(data) {
    const statuses = ["🕑", "⌛", "❔", "✅", "⛔"];
    let html = "<tbody>";
    data.forEach(obj => {
        const exploit = DOMPurify.sanitize(obj.exploit);
        const flag = DOMPurify.sanitize(obj.flag);
        const timestamp = new Date(obj.timestamp * 1000).toISOString();
        const submission_timestamp =
            obj.submission_timestamp ?
            new Date(obj.submission_timestamp * 1000).toISOString() : "-";
        const lifetime = Math.round(obj.lifetime);
        const system_message = obj.system_message ? DOMPurify.sanitize(obj.system_message) : "-";
        const status = obj.status != null && obj.status < statuses.length ? statuses[obj.status] : statuses[2];
        entry  = `<td>${status}</td>`;
        entry += `<td>${exploit}</td>`;
        entry += `<td>${flag}</td>`;
        entry += `<td>${timestamp}</td>`;
        entry += `<td>${zero_pad(2, Math.floor(lifetime / 60))}:${zero_pad(2, lifetime % 60)}</td>`;
        entry += `<td>${submission_timestamp}</td>`;
        entry += `<td>${system_message}</td>`;
        html += `<tr>${entry}</tr>`;
    });
    html += "</tbody>";
    return html;
}

function build_table(data) {
    if (data.length == 0) {
        return "<p> No data to show :( </p>"
    }
    let html = "<table>"
    html += build_table_header(["Status", "Exploit", "Flag", "Timestamp", "Lifetime", "Submission Timestamp", "System Message"]);
    html += build_table_rows(data);
    html += "</table>"
    return html;
}

function refresh_tables() {
    fetch(`/api/flags?start=${page * rows}&count=${rows}`)
        .then(res => res.json(), () => [])
        .then(data => flags_table.innerHTML = build_table(data));
}

next_page_btn.addEventListener("click", () => change_page(+1));
prev_page_btn.addEventListener("click", () => change_page(-1));
entries_count.addEventListener("change", () => {
    new_value = parseInt(entries_count.value);
    if (new_value < 10) {
        entries_count.value = new_value = 10;
    }
    rows = new_value;
});

setInterval(refresh_tables, 5000);
refresh_tables();