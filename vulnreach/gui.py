"""Beginner-friendly desktop interface for VulnReach."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .api import ScanConfig, analyze_project
from .model import Finding, Verdict
from .report.json_report import build_report, write_report


class VulnReachWindow:
    """Small Tk interface for choosing a project and reading scan evidence."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("VulnReach — Python project security scan")
        self.root.geometry("1040x720")
        self.root.minsize(780, 560)
        self.result = None
        self.findings: list[Finding] = []

        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")

        outer = ttk.Frame(root, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Scan a Python project", font=("Segoe UI", 20, "bold")).pack(
            anchor="w"
        )
        ttk.Label(
            outer,
            text=(
                "Choose a project folder. VulnReach checks dependency advisories and shows "
                "the code paths it could confirm. A clean scan is not proof that a project is safe."
            ),
            wraplength=950,
        ).pack(anchor="w", pady=(4, 14))

        project_row = ttk.Frame(outer)
        project_row.pack(fill="x")
        ttk.Label(project_row, text="Project folder").pack(side="left")
        self.path_var = tk.StringVar(value=str(Path.cwd()))
        self.path_entry = ttk.Entry(project_row, textvariable=self.path_var)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=8)
        self.browse_button = ttk.Button(project_row, text="Browse…", command=self._browse_project)
        self.browse_button.pack(side="left")

        options = ttk.Frame(outer)
        options.pack(fill="x", pady=(10, 12))
        self.offline_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options,
            text="Offline mode (use local advisories/cache)",
            variable=self.offline_var,
        ).pack(side="left")
        self.dev_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options, text="Include dev/test dependencies", variable=self.dev_var).pack(
            side="left", padx=(18, 0)
        )
        self.scan_button = ttk.Button(options, text="Scan project", command=self._scan)
        self.scan_button.pack(side="right")

        advisory_row = ttk.Frame(outer)
        advisory_row.pack(fill="x", pady=(0, 10))
        ttk.Label(advisory_row, text="Local advisories (optional)").pack(side="left")
        self.advisory_var = tk.StringVar()
        ttk.Entry(advisory_row, textvariable=self.advisory_var).pack(
            side="left", fill="x", expand=True, padx=8
        )
        ttk.Button(advisory_row, text="Browse…", command=self._browse_advisories).pack(side="left")

        self.status_var = tk.StringVar(
            value="Ready. Online scans use OSV and need internet access."
        )
        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w", pady=(0, 10))

        self.summary_var = tk.StringVar(value="No scan yet")
        ttk.Label(outer, textvariable=self.summary_var, font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 8)
        )

        split = ttk.Panedwindow(outer, orient="horizontal")
        split.pack(fill="both", expand=True)
        left = ttk.Frame(split, padding=(0, 0, 10, 0))
        right = ttk.Frame(split)
        split.add(left, weight=2)
        split.add(right, weight=3)

        ttk.Label(
            left, text="Findings (select one for details)", font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", pady=(0, 6))
        self.finding_list = tk.Listbox(left, activestyle="dotbox", exportselection=False)
        list_scroll = ttk.Scrollbar(left, orient="vertical", command=self.finding_list.yview)
        self.finding_list.configure(yscrollcommand=list_scroll.set)
        self.finding_list.pack(side="left", fill="both", expand=True)
        list_scroll.pack(side="right", fill="y")
        self.finding_list.bind("<<ListboxSelect>>", self._show_selected)

        ttk.Label(right, text="Evidence and scan details", font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        self.details = tk.Text(right, wrap="word", height=16, state="disabled", padx=10, pady=10)
        details_scroll = ttk.Scrollbar(right, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=details_scroll.set)
        self.details.pack(side="left", fill="both", expand=True)
        details_scroll.pack(side="right", fill="y")
        self._set_details(
            "Start a scan to see dependencies, findings, evidence paths, and analysis caveats here."
        )

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(12, 0))
        self.export_button = ttk.Button(
            footer, text="Save JSON report…", command=self._export, state="disabled"
        )
        self.export_button.pack(side="right")
        ttk.Label(footer, text="VulnReach reports evidence; review uncertain results.").pack(
            side="left"
        )

    def _browse_project(self) -> None:
        selected = filedialog.askdirectory(title="Choose your Python project folder")
        if selected:
            self.path_var.set(selected)

    def _browse_advisories(self) -> None:
        selected = filedialog.askdirectory(title="Choose a folder containing OSV JSON files")
        if selected:
            self.advisory_var.set(selected)

    def _scan(self) -> None:
        project = Path(self.path_var.get().strip()).expanduser()
        if not project.is_dir():
            messagebox.showerror("Folder not found", "Choose an existing project folder.")
            return

        self.result = None
        self.findings = []
        self.finding_list.delete(0, "end")
        self.summary_var.set("Scanning…")
        self.status_var.set("Reading Python files and dependency versions…")
        self.scan_button.configure(state="disabled")
        self.browse_button.configure(state="disabled")
        self.export_button.configure(state="disabled")

        config = ScanConfig(
            root=project,
            include_dev=self.dev_var.get(),
            offline=self.offline_var.get(),
            advisory_dirs=(Path(self.advisory_var.get().strip()),)
            if self.advisory_var.get().strip()
            else (),
        )
        threading.Thread(target=self._scan_worker, args=(config,), daemon=True).start()

    def _scan_worker(self, config: ScanConfig) -> None:
        try:
            result = analyze_project(config)
        except Exception as exc:  # Present expected and unexpected scan errors in the UI.
            self.root.after(0, self._scan_failed, str(exc))
            return
        self.root.after(0, self._scan_complete, result)

    def _scan_failed(self, error: str) -> None:
        self.scan_button.configure(state="normal")
        self.browse_button.configure(state="normal")
        self.summary_var.set("Scan did not complete")
        self.status_var.set("Check the folder, internet connection, or offline advisory data.")
        self._set_details(error)
        messagebox.showerror("Scan error", error)

    def _scan_complete(self, result) -> None:
        self.result = result
        self.findings = result.findings
        self.scan_button.configure(state="normal")
        self.browse_button.configure(state="normal")
        self.export_button.configure(state="normal")

        counts = result.summary
        self.summary_var.set(
            f"{counts['reachable']} reachable   ·   {counts['uncertain']} uncertain   ·   "
            f"{counts['not_reachable']} no path found"
        )
        self.status_var.set(
            f"Finished: {result.project.name} · {len(result.dependencies)} dependencies · "
            f"{result.metrics.modules_scanned} Python files · "
            f"{result.metrics.resolution_coverage:.0%} "
            "of calls resolved"
        )

        if self.findings:
            order = {Verdict.REACHABLE: 0, Verdict.UNCERTAIN: 1, Verdict.NOT_REACHABLE: 2}
            self.findings.sort(
                key=lambda item: (order[item.verdict], -item.advisory.severity_rank, item.id)
            )
            for finding in self.findings:
                self.finding_list.insert(
                    "end",
                    f"{finding.verdict.value.replace('_', ' ').upper()}  ·  "
                    f"{finding.dependency.name} "
                    f"{finding.dependency.version or '(version unknown)'}  ·  "
                    f"{finding.advisory.id}",
                )
            self.finding_list.selection_set(0)
            self._render_finding(self.findings[0])
        else:
            self._render_overview()

    def _render_overview(self) -> None:
        result = self.result
        if result is None:
            return
        lines = [
            "No matching advisory findings were returned for the resolved dependency versions.",
            "",
        ]
        lines.append("Dependencies checked:")
        if result.dependencies:
            lines.extend(
                f"• {dep.name} {dep.version or '(version unknown)'} — {dep.version_source}"
                for dep in result.dependencies
            )
        else:
            lines.append("• No dependencies were discovered from supported manifests.")
        lines.extend(
            [
                "",
                f"Advisories considered: {result.metrics.advisories_considered}",
                f"Python modules scanned: {result.metrics.modules_scanned}",
                f"Calls resolved: {result.metrics.reachable_resolution_coverage:.0%}",
                f"Dynamic or unresolved analysis gaps: {len(result.gaps)}",
                "",
                "Interpretation: no matching known advisory was found. "
                "This does not prove the project is vulnerability-free.",
            ]
        )
        if result.warnings:
            lines.extend(["", "Warnings:", *(f"• {warning}" for warning in result.warnings)])
        self._set_details("\n".join(lines))

    def _show_selected(self, _event=None) -> None:
        selection = self.finding_list.curselection()
        if selection and selection[0] < len(self.findings):
            self._render_finding(self.findings[selection[0]])

    def _render_finding(self, finding: Finding) -> None:
        lines = [
            f"{finding.verdict.value.replace('_', ' ').upper()} — {finding.advisory.id}",
            f"Package: {finding.dependency.name}",
            f"Version: {finding.dependency.version or 'unknown'} "
            f"({finding.dependency.version_source})",
            f"Severity: {finding.advisory.severity}",
            f"Confidence: {finding.confidence:.0%}",
            "",
            finding.advisory.summary or "No advisory summary provided.",
            "",
            "Why this result:",
            *(f"• {item.message}" for item in finding.rationale),
        ]
        if finding.paths:
            lines.extend(["", "Evidence path:"])
            for path in finding.paths:
                lines.append(" → ".join(label for _, label in path.nodes))
                for hop in path.hops:
                    if hop.location:
                        lines.append(
                            f"   {hop.location.path}:{hop.location.line} [{hop.kind.value}]"
                        )
        if finding.vulnerable_symbols:
            lines.extend(
                [
                    "",
                    "Advisory vulnerable symbols:",
                    *(f"• {s}" for s in finding.vulnerable_symbols),
                ]
            )
        if finding.uncertainty:
            lines.extend(["", "Analysis gaps for this finding:"])
            lines.extend(
                f"• {gap.kind.value} at {gap.location}: {gap.detail}" for gap in finding.uncertainty
            )
        if finding.advisory.url:
            lines.extend(["", f"Advisory: {finding.advisory.url}"])
        lines.extend(
            [
                "",
                "A result describes static evidence in the scanned project. "
                "It is not a proof of exploitability or safety.",
            ]
        )
        self._set_details("\n".join(lines))

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _export(self) -> None:
        if self.result is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save VulnReach JSON report",
            defaultextension=".json",
            initialfile="vulnreach-report.json",
            filetypes=[("JSON report", "*.json")],
        )
        if not path:
            return
        try:
            write_report(build_report(self.result), Path(path))
        except OSError as exc:
            messagebox.showerror("Could not save report", str(exc))
            return
        self.status_var.set(f"Report saved to {path}")


def launch_gui() -> int:
    """Start the desktop interface. Returns 1 when Tk is unavailable."""
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        messagebox.showerror("VulnReach UI unavailable", f"Could not open the desktop UI: {exc}")
        return 1
    VulnReachWindow(root)
    root.mainloop()
    return 0
