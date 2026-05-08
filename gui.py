import tkinter as tk
from tkinter import ttk
import threading
import sys
import io
import matplotlib
from tkinter import filedialog

matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from rsa import RSACompleteTesting


P = dict(
    BG="#0F1117",
    SIDEBAR="#161B27",
    PANEL="#1C2236",
    CHART_BG="#10141F",
    BORDER="#2A3150",
    ACCENT="#4F8EF7",
    ACCENT2="#7C5CFC",
    SUCCESS="#3DD68C",
    WARNING="#F5A623",
    DANGER="#F75555",
    TEXT="#E8EAF2",
    MUTED="#6B7499",
    HDR="#1C2236",
)


class TextRedirector(io.StringIO):
    def __init__(self, widget, tag_resolver):
        super().__init__()
        self.widget = widget
        self.tag_resolver = tag_resolver

    def write(self, s):
        if not s:
            return
        tag = self.tag_resolver(s)
        self.widget.configure(state="normal")
        self.widget.insert(tk.END, s, tag)
        self.widget.see(tk.END)
        self.widget.configure(state="disabled")

    def flush(self):
        pass


def _style_ax(ax):
    ax.set_facecolor(P["CHART_BG"])
    for sp in ax.spines.values():
        sp.set_edgecolor(P["BORDER"])
    ax.tick_params(colors=P["MUTED"], labelsize=7)
    ax.xaxis.label.set_color(P["MUTED"])
    ax.yaxis.label.set_color(P["MUTED"])
    ax.title.set_color(P["TEXT"])


def _style_fig(fig):
    fig.patch.set_facecolor(P["CHART_BG"])


def _no_data(ax, msg="— rulează testul pentru date reale —"):
    ax.cla()
    _style_ax(ax)
    ax.text(
        0.5,
        0.5,
        msg,
        ha="center",
        va="center",
        color=P["MUTED"],
        fontsize=9,
        transform=ax.transAxes,
        style="italic",
    )
    ax.set_xticks([])
    ax.set_yticks([])


class BaseChart:
    """Each subclass owns one Figure embedded in a given tk Frame."""

    def __init__(self, parent, nrows=1, ncols=1, figsize=(5, 4)):
        self.fig = Figure(figsize=figsize, dpi=96)
        _style_fig(self.fig)
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.axes = []
        for i in range(nrows * ncols):
            ax = self.fig.add_subplot(nrows, ncols, i + 1)
            _style_ax(ax)
            _no_data(ax)
            self.axes.append(ax)
        self.fig.tight_layout(pad=1.8)
        self.canvas.draw()

    def refresh(self):
        try:
            self.fig.tight_layout(pad=1.8)
            self.canvas.draw_idle()
        except Exception:
            pass


class Chart1(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=1, ncols=2, figsize=(6, 3.2))
        self.axes[0].set_title("Timp Factorizare (ms)", fontsize=8)
        self.axes[1].set_title("Chei Factorizate vs Nefactorizate", fontsize=8)

    def update(self, results):
        if not results:
            return
        ax_t, ax_p = self.axes

        ax_t.cla()
        _style_ax(ax_t)
        ax_t.set_title("Timp Factorizare (ms)", fontsize=8, color=P["TEXT"])

        labels = [f"{r['method'][:6]}\n{r['key_size']}b" for r in results]
        times = [r["time_ms"] for r in results]
        colors = [P["SUCCESS"] if r["factorized"] else P["DANGER"] for r in results]
        bars = ax_t.bar(range(len(labels)), times, color=colors, width=0.55, alpha=0.85)
        ax_t.set_xticks(range(len(labels)))
        ax_t.set_xticklabels(labels, fontsize=6, color=P["MUTED"])
        ax_t.set_ylabel("ms", fontsize=7)
        for bar, t in zip(bars, times):
            ax_t.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(times) * 0.01,
                f"{t:.1f}",
                ha="center",
                va="bottom",
                fontsize=6,
                color=P["TEXT"],
            )

        ax_p.cla()
        _style_ax(ax_p)
        ax_p.set_title("Factorizat / Nefactorizat", fontsize=8, color=P["TEXT"])
        fact = sum(1 for r in results if r["factorized"])
        nfact = len(results) - fact
        if fact + nfact > 0:
            wedges, texts, autotexts = ax_p.pie(
                [fact, nfact],
                labels=["Factorizat", "Nefactorizat"],
                colors=[P["SUCCESS"], P["DANGER"]],
                autopct="%1.0f%%",
                startangle=90,
                wedgeprops=dict(width=0.55, edgecolor=P["CHART_BG"], linewidth=1.5),
                textprops=dict(color=P["MUTED"], fontsize=7),
            )
            for at in autotexts:
                at.set_color(P["TEXT"])
                at.set_fontsize(7)

        self.refresh()


class Chart2(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=1, ncols=2, figsize=(6, 3.2))
        self.axes[0].set_title("Rezistență la Atacuri", fontsize=8)
        self.axes[1].set_title("Entropie Ciphertext", fontsize=8)

    def update(self, results):
        if not results:
            return
        ax_r, ax_e = self.axes

        ax_r.cla()
        _style_ax(ax_r)
        ax_r.set_title("Rezistență la Atacuri", fontsize=8, color=P["TEXT"])

        names = [r["attack_type"].replace("_", " ").title() for r in results]
        values = [1 if r.get("resistant", False) else 0 for r in results]
        colors = [P["SUCCESS"] if v else P["WARNING"] for v in values]

        y = np.arange(len(names))
        ax_r.barh(y, [1] * len(names), color=P["BORDER"], height=0.5, alpha=0.4)
        ax_r.barh(y, values, color=colors, height=0.5, alpha=0.9)
        ax_r.set_yticks(y)
        ax_r.set_yticklabels(names, fontsize=7, color=P["MUTED"])
        ax_r.set_xlim(0, 1.3)
        ax_r.set_xticks([])
        for yi, (v, c) in enumerate(zip(values, colors)):
            label = "Rezistent" if v else "Vulnerabil"
            ax_r.text(v + 0.03, yi, label, va="center", fontsize=7, color=c)

        ax_e.cla()
        _style_ax(ax_e)
        ax_e.set_title("Entropie Ciphertext (max=8)", fontsize=8, color=P["TEXT"])
        ent_res = next((r for r in results if "entropy" in r), None)
        if ent_res:
            val = ent_res["entropy"]
            ax_e.barh([0], [8], color=P["BORDER"], height=0.4, alpha=0.4)
            col = P["SUCCESS"] if val > 7.5 else P["WARNING"]
            ax_e.barh([0], [val], color=col, height=0.4, alpha=0.9)
            ax_e.set_xlim(0, 8.5)
            ax_e.set_yticks([])
            ax_e.set_xticks([0, 2, 4, 6, 7.5, 8])
            ax_e.set_xticklabels(
                ["0", "2", "4", "6", "7.5", "8"], fontsize=7, color=P["MUTED"]
            )
            ax_e.text(
                val + 0.05, 0, f"{val:.3f}", va="center", fontsize=8, color=P["TEXT"]
            )
            ax_e.axvline(
                7.5, color=P["ACCENT"], linestyle="--", linewidth=0.8, alpha=0.7
            )
            ax_e.text(7.5, 0.28, "ideal", fontsize=6, color=P["ACCENT"], ha="center")

        self.refresh()


class Chart3(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=1, ncols=2, figsize=(6, 3.2))

    def update(self, result):
        if not result:
            return
        ax_d, ax_p = self.axes

        ax_d.cla()
        _style_ax(ax_d)
        ax_d.set_title(
            "Vulnerabilități vs Practici Sigure", fontsize=8, color=P["TEXT"]
        )
        vuln = result.get("total_vulnerabilities", 0)
        safe = result.get("safe_practices_checked", 0)
        total = vuln + safe
        if total:
            wedges, _ = ax_d.pie(
                [vuln, safe],
                colors=[P["DANGER"], P["SUCCESS"]],
                startangle=90,
                wedgeprops=dict(width=0.5, edgecolor=P["CHART_BG"], linewidth=1.5),
            )
            ax_d.text(
                0,
                0,
                f"{vuln}\nvuln",
                ha="center",
                va="center",
                fontsize=9,
                fontweight="bold",
                color=P["DANGER"],
            )
            patches = [
                mpatches.Patch(color=P["DANGER"], label=f"Vulnerabilități ({vuln})"),
                mpatches.Patch(color=P["SUCCESS"], label=f"Practici sigure ({safe})"),
            ]
            ax_d.legend(
                handles=patches,
                loc="lower center",
                fontsize=7,
                frameon=False,
                labelcolor=P["MUTED"],
                bbox_to_anchor=(0.5, -0.18),
            )

        ax_p.cla()
        _style_ax(ax_p)
        ax_p.set_title("Detalii Vulnerabilități Găsite", fontsize=8, color=P["TEXT"])
        vulns = result.get("vulnerabilities", [])
        if vulns:
            y = np.arange(len(vulns))
            ax_p.barh(y, [1] * len(vulns), color=P["DANGER"], height=0.45, alpha=0.75)
            ax_p.set_yticks(y)
            short = [v[:28] + "…" if len(v) > 28 else v for v in vulns]
            ax_p.set_yticklabels(short, fontsize=6, color=P["MUTED"])
            ax_p.set_xticks([])
        else:
            ax_p.text(
                0.5,
                0.5,
                "✓ Nicio vulnerabilitate găsită",
                ha="center",
                va="center",
                color=P["SUCCESS"],
                fontsize=9,
                transform=ax_p.transAxes,
            )
            ax_p.set_xticks([])
            ax_p.set_yticks([])

        self.refresh()


class Chart4(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=1, ncols=2, figsize=(6, 3.2))

    def update(self, results):
        if not results:
            return
        ax_s, ax_r = self.axes

        ax_s.cla()
        _style_ax(ax_s)
        ax_s.set_title("Rată Succes / Stabilitate", fontsize=8, color=P["TEXT"])
        labels, rates, colors = [], [], []
        for r in results:
            if r["test"] == "stress_volume":
                labels.append("Volume\nMari")
                rates.append(r["success_rate"] * 100)
                colors.append(
                    P["SUCCESS"] if r["success_rate"] >= 0.95 else P["WARNING"]
                )
            elif r["test"] == "stability":
                err = r["errors"]
                total = r["operations"]
                labels.append("Stabilitate")
                rates.append((1 - err / total) * 100)
                colors.append(P["SUCCESS"] if err == 0 else P["DANGER"])

        if labels:
            x = np.arange(len(labels))
            bars = ax_s.bar(x, rates, color=colors, width=0.5, alpha=0.85)
            ax_s.set_xticks(x)
            ax_s.set_xticklabels(labels, fontsize=7, color=P["MUTED"])
            ax_s.set_ylim(0, 110)
            ax_s.axhline(100, color=P["BORDER"], linestyle="--", linewidth=0.7)
            ax_s.set_ylabel("%", fontsize=7)
            for bar, rate in zip(bars, rates):
                ax_s.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 1,
                    f"{rate:.1f}%",
                    ha="center",
                    va="bottom",
                    fontsize=7,
                    color=P["TEXT"],
                )

        ax_r.cla()
        _style_ax(ax_r)
        ax_r.set_title(
            "Reziliență Penetrare (mesaje malformate)", fontsize=8, color=P["TEXT"]
        )
        pen = next((r for r in results if r["test"] == "penetration_malformed"), None)
        if pen:
            score = pen["resilience_score"]
            total = pen["total_tests"]
            fail = total - score
            wedges, _ = ax_r.pie(
                [score, fail],
                colors=[P["SUCCESS"], P["DANGER"]],
                startangle=90,
                wedgeprops=dict(width=0.52, edgecolor=P["CHART_BG"], linewidth=1.5),
            )
            ax_r.text(
                0,
                0,
                f"{score}/{total}",
                ha="center",
                va="center",
                fontsize=12,
                fontweight="bold",
                color=P["TEXT"],
            )
            patches = [
                mpatches.Patch(color=P["SUCCESS"], label="Respinse corect"),
                mpatches.Patch(color=P["DANGER"], label="Erori"),
            ]
            ax_r.legend(
                handles=patches,
                loc="lower center",
                fontsize=7,
                frameon=False,
                labelcolor=P["MUTED"],
                bbox_to_anchor=(0.5, -0.18),
            )

        self.refresh()


class Chart5(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=1, ncols=2, figsize=(6, 3.2))

    def update(self, result):
        if not result:
            return
        ax_b, ax_d = self.axes
        cr = result.get("compliance_results", {})

        ax_b.cla()
        _style_ax(ax_b)
        ax_b.set_title("Conformitate per Standard", fontsize=8, color=P["TEXT"])
        if cr:
            labels = list(cr.keys())
            vals = [1 if v else 0 for v in cr.values()]
            colors = [P["SUCCESS"] if v else P["DANGER"] for v in vals]
            y = np.arange(len(labels))
            ax_b.barh(y, [1] * len(labels), color=P["BORDER"], height=0.5, alpha=0.3)
            ax_b.barh(y, vals, color=colors, height=0.5, alpha=0.85)
            ax_b.set_yticks(y)
            ax_b.set_yticklabels(labels, fontsize=6.5, color=P["MUTED"])
            ax_b.set_xlim(0, 1.3)
            ax_b.set_xticks([])
            for yi, (v, c) in enumerate(zip(vals, colors)):
                ax_b.text(
                    v + 0.03, yi, "✓" if v else "✗", va="center", fontsize=8, color=c
                )

        ax_d.cla()
        _style_ax(ax_d)
        ax_d.set_title("Rată Conformitate Globală", fontsize=8, color=P["TEXT"])
        passed = result.get("passed_checks", 0)
        total = result.get("total_checks", 1)
        failed = total - passed
        if total:
            ax_d.pie(
                [passed, failed],
                colors=[P["SUCCESS"], P["DANGER"]],
                startangle=90,
                wedgeprops=dict(width=0.48, edgecolor=P["CHART_BG"], linewidth=1.5),
            )
            pct = passed / total * 100
            col = P["SUCCESS"] if pct >= 80 else P["WARNING"]
            ax_d.text(
                0,
                0,
                f"{pct:.0f}%",
                ha="center",
                va="center",
                fontsize=14,
                fontweight="bold",
                color=col,
            )
            patches = [
                mpatches.Patch(color=P["SUCCESS"], label=f"Conform ({passed})"),
                mpatches.Patch(color=P["DANGER"], label=f"Neconform ({failed})"),
            ]
            ax_d.legend(
                handles=patches,
                loc="lower center",
                fontsize=7,
                frameon=False,
                labelcolor=P["MUTED"],
                bbox_to_anchor=(0.5, -0.18),
            )

        self.refresh()


class Chart6(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=2, ncols=1, figsize=(5, 4))

    def update(self, results):
        if not results:
            return
        ax_g, ax_ed = self.axes

        sizes = [r["key_size"] for r in results]
        gen_t = [r["key_gen_time"] for r in results]
        enc_t = [r["encrypt_time"] for r in results]
        dec_t = [r["decrypt_time"] for r in results]
        x = np.arange(len(sizes))

        ax_g.cla()
        _style_ax(ax_g)
        ax_g.set_title("Generare Chei (ms)", fontsize=8, color=P["TEXT"])
        bars = ax_g.bar(x, gen_t, color=P["ACCENT"], width=0.5, alpha=0.85)
        ax_g.set_xticks(x)
        ax_g.set_xticklabels([f"{s}b" for s in sizes], fontsize=7, color=P["MUTED"])
        ax_g.set_ylabel("ms", fontsize=7)
        for bar, t in zip(bars, gen_t):
            ax_g.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(gen_t) * 0.02,
                f"{t:.1f}",
                ha="center",
                va="bottom",
                fontsize=6,
                color=P["TEXT"],
            )

        ax_ed.cla()
        _style_ax(ax_ed)
        ax_ed.set_title("Criptare vs Decriptare (ms)", fontsize=8, color=P["TEXT"])
        w = 0.3
        b1 = ax_ed.bar(
            x - w / 2, enc_t, w, color=P["SUCCESS"], label="Criptare", alpha=0.85
        )
        b2 = ax_ed.bar(
            x + w / 2, dec_t, w, color=P["WARNING"], label="Decriptare", alpha=0.85
        )
        ax_ed.set_xticks(x)
        ax_ed.set_xticklabels([f"{s}b" for s in sizes], fontsize=7, color=P["MUTED"])
        ax_ed.set_ylabel("ms", fontsize=7)
        ax_ed.legend(fontsize=7, frameon=False, labelcolor=P["MUTED"])
        for bar, t in zip(list(b1) + list(b2), enc_t + dec_t):
            ax_ed.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.001,
                f"{t:.2f}",
                ha="center",
                va="bottom",
                fontsize=5.5,
                color=P["TEXT"],
            )

        self.refresh()


class Chart7(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=1, ncols=2, figsize=(6, 3.2))

    def update(self, results):
        if not results:
            return
        ax_b, ax_d = self.axes

        ax_b.cla()
        _style_ax(ax_b)
        ax_b.set_title("Rezultate Sub-Teste Integritate", fontsize=8, color=P["TEXT"])
        names, vals, colors = [], [], []
        for r in results:
            name = r.get("test", "?").replace("_", " ").title()
            if "passed" in r:
                passed = r["passed"]
            else:
                passed = r.get("signature_valid", False) and r.get(
                    "tamper_detected", False
                )
            names.append(name)
            vals.append(1 if passed else 0)
            colors.append(P["SUCCESS"] if passed else P["DANGER"])

        y = np.arange(len(names))
        ax_b.barh(y, [1] * len(names), color=P["BORDER"], height=0.45, alpha=0.35)
        ax_b.barh(y, vals, color=colors, height=0.45, alpha=0.9)
        ax_b.set_yticks(y)
        ax_b.set_yticklabels(names, fontsize=7, color=P["MUTED"])
        ax_b.set_xlim(0, 1.3)
        ax_b.set_xticks([])
        for yi, (v, c) in enumerate(zip(vals, colors)):
            ax_b.text(
                v + 0.03,
                yi,
                "TRECUT" if v else "EȘUAT",
                va="center",
                fontsize=7,
                color=c,
            )

        ax_d.cla()
        _style_ax(ax_d)
        ax_d.set_title("Sumar Integritate", fontsize=8, color=P["TEXT"])
        total = len(vals)
        passed = sum(vals)
        failed = total - passed
        if total:
            ax_d.pie(
                [passed, failed],
                colors=[P["SUCCESS"], P["DANGER"]],
                startangle=90,
                wedgeprops=dict(width=0.5, edgecolor=P["CHART_BG"], linewidth=1.5),
            )
            ax_d.text(
                0,
                0,
                f"{passed}/{total}",
                ha="center",
                va="center",
                fontsize=13,
                fontweight="bold",
                color=P["SUCCESS"] if passed == total else P["WARNING"],
            )

        self.refresh()


class Chart8(BaseChart):
    def __init__(self, parent):
        super().__init__(parent, nrows=2, ncols=2, figsize=(6, 4))

    def update(self, result):
        if not result:
            return
        ax1, ax2, ax3, ax4 = self.axes

        # ─ Entropy gauge ─
        ax1.cla()
        _style_ax(ax1)
        ax1.set_title("Entropie Shannon (ideal 8.0)", fontsize=7, color=P["TEXT"])
        val = result.get("entropy_mean", 0)
        std = result.get("entropy_std", 0)
        ax1.barh([0], [8], color=P["BORDER"], height=0.4, alpha=0.4)
        col = P["SUCCESS"] if val > 7.9 else P["WARNING"]
        ax1.barh([0], [val], color=col, height=0.4, alpha=0.9)
        ax1.set_xlim(0, 8.5)
        ax1.set_yticks([])
        ax1.set_xticks([0, 4, 7.9, 8])
        ax1.set_xticklabels(["0", "4", "7.9", "8"], fontsize=6, color=P["MUTED"])
        ax1.axvline(7.9, color=P["ACCENT"], linestyle="--", linewidth=0.8)
        ax1.text(
            val - 0.05,
            0,
            f"{val:.4f}±{std:.4f}",
            va="center",
            ha="right",
            fontsize=7,
            color=P["TEXT"],
            fontweight="bold",
        )

        # ─ Bit distribution gauge ─
        ax2.cla()
        _style_ax(ax2)
        ax2.set_title("Distribuție Biți (ideal 0.5)", fontsize=7, color=P["TEXT"])
        bm = result.get("bit_distribution_mean", 0)
        bst = result.get("bit_distribution_std", 0)
        ax2.barh([0], [1], color=P["BORDER"], height=0.4, alpha=0.4)
        col2 = P["SUCCESS"] if abs(bm - 0.5) < 0.01 else P["WARNING"]
        ax2.barh([0], [bm], color=col2, height=0.4, alpha=0.9)
        ax2.set_xlim(0, 1.1)
        ax2.set_yticks([])
        ax2.axvline(0.5, color=P["ACCENT"], linestyle="--", linewidth=0.8)
        ax2.text(
            bm + 0.01,
            0,
            f"{bm:.4f}",
            va="center",
            ha="left",
            fontsize=7,
            color=P["TEXT"],
            fontweight="bold",
        )

        ax3.cla()
        _style_ax(ax3)
        ax3.set_title("Chi-Pătrat (limită 20)", fontsize=7, color=P["TEXT"])
        chi = result.get("chi_square", 0)
        display_chi = min(chi, 40)
        col3 = P["SUCCESS"] if chi < 20 else P["DANGER"]
        ax3.barh([0], [40], color=P["BORDER"], height=0.4, alpha=0.4)
        ax3.barh([0], [display_chi], color=col3, height=0.4, alpha=0.9)
        ax3.axvline(20, color=P["WARNING"], linestyle="--", linewidth=0.8)
        ax3.set_xlim(0, 45)
        ax3.set_yticks([])
        ax3.set_xticks([0, 10, 20, 30, 40])
        ax3.set_xticklabels(["0", "10", "20", "30", "40"], fontsize=6, color=P["MUTED"])
        ax3.text(
            display_chi + 0.5, 0, f"{chi:.2f}", va="center", fontsize=7, color=P["TEXT"]
        )

        # ─ Radar-style summary ─
        ax4.cla()
        _style_ax(ax4)
        ax4.set_title("Sumar Calitate", fontsize=7, color=P["TEXT"])
        metrics = ["Entropie", "Distribuție\nBiți", "Chi²\n(inv)"]
        ent_score = min(val / 8.0, 1.0)
        bit_score = max(0, 1 - abs(bm - 0.5) / 0.1)
        chi_score = max(0, 1 - chi / 40)
        scores = [ent_score, bit_score, chi_score]
        colors = [
            P["SUCCESS"] if s > 0.9 else P["WARNING"] if s > 0.6 else P["DANGER"]
            for s in scores
        ]
        x = np.arange(len(metrics))
        bars = ax4.bar(x, scores, color=colors, width=0.5, alpha=0.85)
        ax4.set_xticks(x)
        ax4.set_xticklabels(metrics, fontsize=6, color=P["MUTED"])
        ax4.set_ylim(0, 1.2)
        ax4.axhline(0.9, color=P["BORDER"], linestyle="--", linewidth=0.7)
        for bar, s in zip(bars, scores):
            ax4.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.02,
                f"{s:.2f}",
                ha="center",
                va="bottom",
                fontsize=7,
                color=P["TEXT"],
            )

        self.refresh()


TESTS_META = [
    ("01", "Complexitate", "Evaluare algoritm, factorizare"),
    ("02", "Atacuri", "Criptanaliză CPA/COA"),
    ("03", "Vulnerabilități", "Audit manual securitate"),
    ("04", "Stress Test", "Simulări și penetrare"),
    ("05", "Standarde", "NIST / FIPS / PCI-DSS"),
    ("06", "Performanță", "Timpi generare/criptare"),
    ("07", "Integritate", "Hash, HMAC, Semnături"),
    ("08", "Entropie", "Randomizare și entropie"),
]


class RSAGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Testarea Algoritmului RSA")
        self.root.geometry("1460x840")
        self.root.minsize(1100, 680)
        self.root.configure(bg=P["BG"])

        self.suite = RSACompleteTesting()
        self.running = False
        self.test_states = {i: "idle" for i in range(8)}
        self.btn_widgets = {}

        self._configure_styles()
        self._build_ui()
        self._redirect_stdout()
        self._print_banner()

    def _configure_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(
            "TScrollbar",
            background=P["PANEL"],
            troughcolor=P["BG"],
            bordercolor=P["BG"],
            arrowcolor=P["MUTED"],
        )
        s.configure(
            "Thin.Horizontal.TProgressbar",
            troughcolor=P["BORDER"],
            background=P["ACCENT"],
            bordercolor=P["PANEL"],
            lightcolor=P["ACCENT"],
            darkcolor=P["ACCENT"],
        )
        # notebook tabs
        s.configure(
            "Dark.TNotebook",
            background=P["PANEL"],
            bordercolor=P["BORDER"],
            tabmargins=[0, 0, 0, 0],
        )
        s.configure(
            "Dark.TNotebook.Tab",
            background=P["BORDER"],
            foreground=P["MUTED"],
            font=("Courier", 8, "bold"),
            padding=[8, 4],
        )
        s.map(
            "Dark.TNotebook.Tab",
            background=[("selected", P["ACCENT"]), ("active", P["PANEL"])],
            foreground=[("selected", "#fff"), ("active", P["TEXT"])],
        )

    def _build_ui(self):
        # header
        hdr = tk.Frame(self.root, bg=P["HDR"], height=52)
        hdr.pack(side=tk.TOP, fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(
            hdr, text="⬡", font=("Courier", 20, "bold"), bg=P["HDR"], fg=P["ACCENT"]
        ).pack(side=tk.LEFT, padx=(18, 6), pady=10)
        tk.Label(
            hdr,
            text="Testarea Algoritmului RSA",
            font=("Courier", 14, "bold"),
            bg=P["HDR"],
            fg=P["TEXT"],
        ).pack(side=tk.LEFT, pady=10)
        tk.Frame(self.root, bg=P["ACCENT"], height=2).pack(fill=tk.X)

        body = tk.Frame(self.root, bg=P["BG"])
        body.pack(fill=tk.BOTH, expand=True)

        self._build_sidebar(body)
        self._build_terminal(body)
        self._build_charts_panel(body)
        self.status_var = tk.StringVar(value="Gata")

        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bg=P["HDR"],
            fg=P["MUTED"],
            font=("Courier", 9),
            anchor="w",
            padx=10,
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _build_sidebar(self, parent):
        sb = tk.Frame(parent, bg=P["SIDEBAR"], width=225)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        sb.pack_propagate(False)

        tk.Label(
            sb,
            text="SUITE DE TESTE",
            font=("Courier", 8, "bold"),
            bg=P["SIDEBAR"],
            fg=P["MUTED"],
        ).pack(anchor="w", padx=15, pady=(16, 6))

        for i, (num, name, desc) in enumerate(TESTS_META):
            self._make_test_btn(sb, i, num, name, desc)

        tk.Frame(sb, bg=P["BORDER"], height=1).pack(fill=tk.X, padx=15, pady=10)

        self._action_btn(sb, "▶  Rulează Toate", self._run_all, P["ACCENT"])
        self._action_btn(sb, "📊  Raport Final", self._run_report, P["ACCENT2"])
        self._action_btn(sb, "✕  Curăță", self._clear, P["MUTED"])

        tk.Frame(sb, bg=P["SIDEBAR"]).pack(fill=tk.Y, expand=True)
        tk.Frame(sb, bg=P["BORDER"], height=1).pack(fill=tk.X)

    def _make_test_btn(self, parent, idx, num, name, desc):
        frame = tk.Frame(parent, bg=P["SIDEBAR"], cursor="hand2")
        frame.pack(fill=tk.X, padx=8, pady=2)

        dot = tk.Label(
            frame,
            text="●",
            font=("Courier", 7),
            bg=P["SIDEBAR"],
            fg=P["BORDER"],
            width=2,
        )
        dot.pack(side=tk.LEFT, padx=(4, 0))

        badge = tk.Label(
            frame,
            text=num,
            font=("Courier", 8, "bold"),
            bg=P["BORDER"],
            fg=P["MUTED"],
            padx=4,
            pady=1,
        )
        badge.pack(side=tk.LEFT, padx=4)

        inner = tk.Frame(frame, bg=P["SIDEBAR"])
        inner.pack(side=tk.LEFT, fill=tk.X, expand=True)

        title = tk.Label(
            inner,
            text=name,
            font=("Courier", 9, "bold"),
            bg=P["SIDEBAR"],
            fg=P["TEXT"],
            anchor="w",
        )
        title.pack(fill=tk.X)

        sub = tk.Label(
            inner,
            text=desc,
            font=("Courier", 7),
            bg=P["SIDEBAR"],
            fg=P["MUTED"],
            anchor="w",
        )
        sub.pack(fill=tk.X)

        runner = self._make_runner(idx)
        hover_bg = "#1E2640"
        for w in (frame, dot, badge, inner, title, sub):
            w.bind("<Button-1>", lambda e, r=runner: r())
            w.bind("<Enter>", lambda e, f=frame, c=hover_bg: self._hover(f, c, True))
            w.bind("<Leave>", lambda e, f=frame: self._hover(f, P["SIDEBAR"], False))

        self.btn_widgets[idx] = dict(dot=dot, badge=badge)
        self.test_states[idx] = "idle"

    def _hover(self, frame, color, on):
        bg = color if on else P["SIDEBAR"]
        frame.configure(bg=bg)
        for w in frame.winfo_children():
            try:
                w.configure(bg=bg)
                for ww in w.winfo_children():
                    ww.configure(bg=bg)
            except Exception:
                pass

    def _action_btn(self, parent, text, cmd, color):
        tk.Button(
            parent,
            text=text,
            font=("Courier", 9, "bold"),
            bg=P["PANEL"],
            fg=color,
            activebackground=P["BORDER"],
            activeforeground=color,
            relief="flat",
            bd=0,
            padx=10,
            pady=7,
            cursor="hand2",
            command=cmd,
        ).pack(fill=tk.X, padx=10, pady=2)

    def _build_terminal(self, parent):
        center = tk.Frame(parent, bg=P["BG"])
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        center.pack_propagate(False)
        center.configure(width=400)

        # stats row
        stats_f = tk.Frame(center, bg=P["PANEL"], height=58)
        stats_f.pack(fill=tk.X, padx=12, pady=(12, 0))
        stats_f.pack_propagate(False)
        self.stat_vars = {}
        for label, val, color in [
            ("TOTAL TESTE", "8", P["ACCENT"]),
            ("FINALIZATE", "0", P["SUCCESS"]),
            ("ÎN RULARE", "0", P["WARNING"]),
            ("EȘUATE", "0", P["DANGER"]),
        ]:
            cell = tk.Frame(stats_f, bg=P["PANEL"])
            cell.pack(side=tk.LEFT, padx=18, pady=8)
            sv = tk.StringVar(value=val)
            self.stat_vars[label] = sv
            tk.Label(
                cell,
                textvariable=sv,
                font=("Courier", 18, "bold"),
                bg=P["PANEL"],
                fg=color,
            ).pack()
            tk.Label(
                cell, text=label, font=("Courier", 7), bg=P["PANEL"], fg=P["MUTED"]
            ).pack()
            if label != "FAIL":
                tk.Frame(stats_f, bg=P["BORDER"], width=1).pack(
                    side=tk.LEFT, fill=tk.Y, pady=6
                )

        # terminal
        th = tk.Frame(center, bg=P["PANEL"], height=28)
        th.pack(fill=tk.X, padx=12, pady=(7, 0))
        th.pack_propagate(False)
        tk.Label(
            th,
            text="  TERMINAL OUTPUT",
            font=("Courier", 8, "bold"),
            bg=P["PANEL"],
            fg=P["MUTED"],
        ).pack(side=tk.LEFT, pady=5)
        for c in ("#F75555", "#F5A623", "#3DD68C"):
            tk.Label(th, text="●", font=("Courier", 9), bg=P["PANEL"], fg=c).pack(
                side=tk.RIGHT, padx=3, pady=5
            )

        outer = tk.Frame(center, bg=P["BORDER"], bd=1)
        outer.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        sb2 = tk.Scrollbar(
            outer,
            bg=P["PANEL"],
            troughcolor=P["BG"],
            activebackground=P["BORDER"],
            relief="flat",
            bd=0,
        )
        sb2.pack(side=tk.RIGHT, fill=tk.Y)
        self.text = tk.Text(
            outer,
            bg="#080C17",
            fg=P["TEXT"],
            font=("Courier", 9),
            relief="flat",
            bd=0,
            wrap=tk.WORD,
            state="disabled",
            yscrollcommand=sb2.set,
            padx=12,
            pady=8,
        )
        self.text.pack(fill=tk.BOTH, expand=True)
        sb2.config(command=self.text.yview)
        self._setup_tags()

    def _setup_tags(self):
        self.text.tag_configure(
            "banner", foreground=P["ACCENT"], font=("Courier", 9, "bold")
        )
        self.text.tag_configure(
            "section", foreground=P["ACCENT2"], font=("Courier", 9, "bold")
        )
        self.text.tag_configure(
            "heading", foreground="#A0B4FF", font=("Courier", 9, "bold")
        )
        self.text.tag_configure("success", foreground=P["SUCCESS"], font=("Courier", 9))
        self.text.tag_configure("warning", foreground=P["WARNING"], font=("Courier", 9))
        self.text.tag_configure("danger", foreground=P["DANGER"], font=("Courier", 9))
        self.text.tag_configure("muted", foreground=P["MUTED"], font=("Courier", 9))
        self.text.tag_configure("normal", foreground=P["TEXT"], font=("Courier", 9))

    def _build_charts_panel(self, parent):
        right = tk.Frame(parent, bg=P["PANEL"])
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        right.pack_propagate(False)
        right.configure(width=600)

        hdr = tk.Frame(right, bg="#141926", height=28)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(
            hdr,
            text="  GRAFICE TESTE",
            font=("Courier", 8, "bold"),
            bg="#141926",
            fg=P["MUTED"],
        ).pack(side=tk.LEFT, pady=5)

        self.nb = ttk.Notebook(right, style="Dark.TNotebook")
        self.nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        chart_classes = [Chart1, Chart2, Chart3, Chart4, Chart5, Chart6, Chart7, Chart8]
        self.chart_tabs = []

        for i, (_, name, _) in enumerate(TESTS_META):
            tab_frame = tk.Frame(self.nb, bg=P["CHART_BG"])
            self.nb.add(tab_frame, text=f" {i+1:02d} ")
            ch = chart_classes[i](tab_frame)
            self.chart_tabs.append(ch)

    def _redirect_stdout(self):
        sys.stdout = TextRedirector(self.text, self._resolve_tag)

    def _resolve_tag(self, text):
        t = text.strip()
        if "=" * 10 in t:
            return "section"
        if t.startswith("---"):
            return "heading"
        if "✓" in t or "TRECUT" in t:
            return "success"
        if "✗" in t or "EȘUATE" in t:
            return "danger"
        if "⚠" in t or "ATENȚIE" in t:
            return "warning"
        if t.startswith("  "):
            return "muted"
        return "normal"

    def _print_banner(self):
        b = (
            "\n"
            "Testarea Algoritmului RSA\n"
            "Selectează un test sau rulează întreaga suită  \n\n"
        )
        self.text.configure(state="normal")
        self.text.insert(tk.END, b, "banner")
        self.text.configure(state="disabled")

    def _make_runner(self, idx):
        funcs = [
            self.suite.test_1_complexity_evaluation,
            self.suite.test_2_cryptanalytic_attacks,
            self.suite.test_3_vulnerability_audit,
            self.suite.test_4_stress_and_penetration,
            self.suite.test_5_standards_compliance,
            lambda: self.suite.test_6_performance(
                key_sizes=[1024, 2048, 3072], iterations=5
            ),
            self.suite.test_7_integrity,
            lambda: self.suite.test_8_entropy_and_randomness(
                key_size=2048, num_keys=20
            ),
        ]

        def runner():
            if self.running:
                return
            threading.Thread(
                target=self._exec_single, args=(idx, funcs[idx]), daemon=True
            ).start()

        return runner

    def _exec_single(self, idx, func):
        self._set_state(idx, "running")
        self._update_stats()
        try:
            func()
            self._set_state(idx, "done")
        except Exception as e:
            print(f"\n✗ Eroare: {e}\n")
            self._set_state(idx, "error")
        finally:
            self._update_stats()
            self.root.after(0, self._refresh_chart, idx)

    def _run_all(self):
        if self.running:
            return

        def job():
            self.running = True
            self.status_var.set("Rulează toate testele...")
            tasks = [
                (0, self.suite.test_1_complexity_evaluation),
                (1, self.suite.test_2_cryptanalytic_attacks),
                (2, self.suite.test_3_vulnerability_audit),
                (3, self.suite.test_4_stress_and_penetration),
                (4, self.suite.test_5_standards_compliance),
                (
                    5,
                    lambda: self.suite.test_6_performance(
                        key_sizes=[1024, 2048, 3072], iterations=5
                    ),
                ),
                (6, self.suite.test_7_integrity),
                (
                    7,
                    lambda: self.suite.test_8_entropy_and_randomness(
                        key_size=2048, num_keys=20
                    ),
                ),
            ]
            for idx, func in tasks:
                self._set_state(idx, "running")
                self._update_stats()
                try:
                    func()
                    self._set_state(idx, "done")
                except Exception as e:
                    print(f"\n✗ Eroare la testul {idx+1}: {e}\n")
                    self._set_state(idx, "error")
                self._update_stats()
                self.root.after(0, self._refresh_chart, idx)
            self.running = False
            self.status_var.set("Toate testele finalizate.")

        threading.Thread(target=job, daemon=True).start()

    def _run_report(self):
        if self.running:
            return

        filename = filedialog.asksaveasfilename(
            title="Salvează raportul PDF",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            initialfile="raport_rsa.pdf",
        )
        if not filename:
            return

        def job():
            try:
                self.suite.export_pdf(
                    self.suite.results, self.chart_tabs, filename=filename
                )
                print(f"\n✓ PDF salvat la: {filename}\n")
            except Exception as e:
                print(f"\n✗ Eroare PDF: {e}\n")

        threading.Thread(target=job, daemon=True).start()

    def _clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", tk.END)
        self.text.configure(state="disabled")
        self._print_banner()
        # reset suite results
        self.suite = RSACompleteTesting()
        for i in range(8):
            self._set_state(i, "idle")
        self._update_stats()
        self.status_var.set("Gata")
        # reset charts
        for ch in self.chart_tabs:
            for ax in ch.axes:
                _no_data(ax)
            ch.refresh()

    def _set_state(self, idx, state):
        self.test_states[idx] = state
        w = self.btn_widgets.get(idx, {})
        dc = {
            "idle": P["BORDER"],
            "running": P["WARNING"],
            "done": P["SUCCESS"],
            "error": P["DANGER"],
        }
        bc = {
            "idle": P["MUTED"],
            "running": P["WARNING"],
            "done": P["SUCCESS"],
            "error": P["DANGER"],
        }
        if w.get("dot"):
            w["dot"].configure(fg=dc.get(state, P["BORDER"]))
        if w.get("badge"):
            w["badge"].configure(fg=bc.get(state, P["MUTED"]))
        names = [t[1] for t in TESTS_META]
        msg = {
            "running": f"Rulează: {names[idx]}...",
            "done": f"Finalizat: {names[idx]}",
            "error": f"Eroare: {names[idx]}",
        }.get(state, "")
        if msg:
            self.status_var.set(msg)

    def _update_stats(self):
        done = sum(1 for s in self.test_states.values() if s == "done")
        running = sum(1 for s in self.test_states.values() if s == "running")
        errors = sum(1 for s in self.test_states.values() if s == "error")
        self.stat_vars["FINALIZATE"].set(str(done + errors))
        self.stat_vars["ÎN RULARE"].set(str(running))
        self.stat_vars["EȘUATE"].set(str(errors))

    # ── chart refresh – called on main thread via root.after() ─────────
    def _refresh_chart(self, idx):
        """Pull real data from suite.results and update the correct tab."""
        r = self.suite.results
        try:
            if idx == 0:
                self.chart_tabs[0].update(r.get("complexity", []))
            elif idx == 1:
                self.chart_tabs[1].update(r.get("cryptanalytic", []))
            elif idx == 2:
                self.chart_tabs[2].update(r.get("vulnerabilities", {}))
            elif idx == 3:
                self.chart_tabs[3].update(r.get("simulations", []))
            elif idx == 4:
                self.chart_tabs[4].update(r.get("standards", {}))
            elif idx == 5:
                self.chart_tabs[5].update(r.get("performance", []))
            elif idx == 6:
                self.chart_tabs[6].update(r.get("integrity", []))
            elif idx == 7:
                self.chart_tabs[7].update(r.get("entropy", {}))
            # auto-switch to the tab that just finished
            self.nb.select(idx)
        except Exception as e:
            print(f"\n⚠ Eroare grafic testul {idx+1}: {e}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = RSAGUI(root)
    root.mainloop()
