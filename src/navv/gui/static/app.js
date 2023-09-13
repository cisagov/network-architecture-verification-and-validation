function enableCreateButton() {
    if (document.getElementById("inputname").value != ""
        && document.getElementById("inputpcapfile").value != ""
        || document.getElementById("inputzeeklogs").value != "") {
        document.getElementById("runanalysis").removeAttribute("disabled");
    }
}