"""HTML for the human-facing pages: the queue table, one alert's status page, the
profiles, configuration and system pages, and the small confirm/file/not-found pages.

Server-rendered, every dynamic value escaped; inline scripts add auto refresh,
local times, menus, dialogs and the row actions. Styled after the
Sycope UI (dark navy panels, grey-blue grid header, outlined monospace state
badges, blue histogram bars) because analysts open these pages from a link in a
Sycope alert, often through Sycope Passthrough, and should feel at home.
"""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import re
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

from sycope_recorder.config_help import CONFIG_HELP
from sycope_recorder.extraction import local_epoch
from sycope_recorder.store import (
    CANCELLED,
    DONE,
    FAILED,
    FIELDS,
    MAIN_SLOT,
    MAX_WINDOW,
    MISS,
    QUEUED,
    RUNNING,
    WORKER_BUSY,
    WORKER_IDLE,
    WORKER_PAUSED,
    WORKER_RUNNING,
    field_token,
    search_tokens,
)

_CSS = """
:root{--bg:#060725;--panel:#20213f;--panel2:#2d2e55;--head:#50516a;--head2:#616179;--row:#2d2e55;--hover:#37385e;
--line:#20213f;--hsep:#20213f;--hline:#808297;--fg:#fff;--mut:#97a1ba;--blue:#1c48f7;--blue2:#2330cf;--bar:#276edb;--cube:#d44ad8;--nul:#808297;
--green:#00a01a;--orange:#ff7a00;--red:#e0122d;--ink:#222957;--pop:#3a3c6e;
--ok:#3ecf72;--okbg:#14382a;--warn:#ff8a3d;--warnbg:#4a2a18;--bad:#ff5d5d;--badbg:#4a1d28;--info:#0f8bfd;--infobg:#17325a}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:linear-gradient(270.34deg,#060725 .33%,#090a30 99.74%) fixed;color:var(--fg);font:14px/1.4 "Kumbh Sans",-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
button,input,select,textarea{font-family:inherit}
a{color:var(--info);text-decoration:none}a:hover{text-decoration:underline}
code,.mono{font-family:"Roboto Mono",ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.top{position:relative;z-index:70;display:flex;align-items:center;gap:14px;padding:0 16px 0 22px;height:48px;background:var(--panel)}
/* Scrollbars as in Sycope dark mode (its styles.css): thin grey thumb on a muted track, wider on hover. The bar keeps
   one width (a bar that widens on hover narrows the content next to it, which then reflows and jumps); the thumb
   looks wider on hover by dropping its transparent border. Firefox gets scrollbar-color only: in Chrome the
   standard property would switch the ::-webkit-scrollbar rules off. */
::-webkit-scrollbar{background:transparent;width:10px;height:10px}
::-webkit-scrollbar-thumb{background:rgb(143,143,157);background-clip:padding-box;border:1px solid transparent;border-radius:2px}
*:hover::-webkit-scrollbar-thumb{border-width:0}
::-webkit-scrollbar-track{background:rgb(75,75,99);border-radius:2px}::-webkit-scrollbar-corner{background:rgb(75,75,99)}
@supports (-moz-appearance:none){*{scrollbar-width:thin;scrollbar-color:rgb(143,143,157) rgb(75,75,99)}}
.logo{display:inline-flex;align-items:center;gap:10px;line-height:1}.logo:hover{text-decoration:none}.logo svg{height:26px;width:auto;margin-top:4px}.logo .lname{font-size:20px;font-weight:400;color:#fff}
.top .sub{color:var(--mut)}.top .sp{flex:1}
.rf{margin:0}.rf button{display:flex;align-items:center;justify-content:center;width:36px;height:34px;padding:0;background:var(--blue);color:#fff;border:0;border-radius:3px;cursor:pointer}
.rf button:hover{background:#3a62ff}
.rfg{position:relative;display:flex;align-items:center;gap:0}.rfg .rf button{border-radius:3px 0 0 3px}
.menu{position:relative}.menu summary{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:4px;background:none;color:#e6e8f0}
.menu summary::-webkit-details-marker{display:none}.menu summary:hover{background:var(--panel2)}
.menup{position:absolute;right:0;top:40px;z-index:20;min-width:200px;display:flex;flex-direction:column;background:var(--panel2);border:1px solid var(--pop);border-radius:5px;padding:6px;box-shadow:0 6px 24px #0008}
.menup a{padding:7px 12px;border-radius:4px;color:var(--fg)}.menup a.cur{background:var(--blue);color:#fff}.menup a:hover{background:var(--head);text-decoration:none}
.dot{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--mut)}.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.fail{background:var(--bad)}.dot.unknown{background:var(--mut)}
.sysgrid{display:grid;grid-template-columns:180px 1fr;gap:6px 16px;align-items:start}.sysgrid h2{margin:6px 0}
.warnbox{background:var(--warnbg);border:1px solid var(--warn);border-radius:6px;padding:8px 12px;margin-bottom:8px}
.info{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;margin-left:4px;border:1px solid var(--mut);border-radius:50%;color:var(--mut);font:italic 700 10px Georgia,serif;cursor:help;vertical-align:middle;text-transform:none}
.info:hover,.info:focus{color:#fff;border-color:var(--info);outline:0}
#tip{position:fixed;z-index:50;display:none;max-width:420px;padding:10px 12px;background:var(--bg);border:1px solid var(--info);border-radius:6px;box-shadow:0 6px 24px #000a;color:var(--fg);font:12px/1.5 inherit;font-weight:400;white-space:pre-line;text-transform:none;letter-spacing:0}
.rfd{display:inline-block}.rfg summary{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:center;width:30px;height:34px;background:var(--blue2);color:#fff;border-radius:0 3px 3px 0}
.rfg summary::-webkit-details-marker{display:none}.rfg summary:hover{background:#2c3ce0}
.rfp{position:absolute;right:0;top:34px;z-index:20;display:flex;align-items:center;gap:12px;white-space:nowrap;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:14px 18px;box-shadow:0 6px 24px #0008}
.rfp input[type=number],.rfp select{background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:5px;padding:6px 8px;font:inherit}
.rfp input[type=number]{width:64px}
.sw{position:relative;display:inline-block;width:42px;height:22px}.sw input{opacity:0;width:0;height:0}
.sw span{position:absolute;inset:0;border-radius:22px;background:var(--head);cursor:pointer;transition:.15s}
.sw span::before{content:"";position:absolute;left:3px;top:3px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.15s}
.sw input:checked+span{background:var(--blue)}.sw input:checked+span::before{transform:translateX(20px)}
.rfst{color:var(--mut);font-size:12px}
.wrap{max-width:1680px;margin:0 auto;padding:16px 32px}
.card{background:var(--panel);border:0;border-radius:5px;padding:16px;margin-bottom:16px}
.card.s-done{border-left:4px solid var(--ok)}.card.s-queued,.card.s-running{border-left:4px solid var(--warn)}
.card.s-miss,.card.s-failed{border-left:4px solid var(--bad)}.card.s-cancelled{border-left:4px solid var(--mut)}.card.s-unknown{border-left:4px solid var(--mut)}
h1{font-size:18px;margin:0 0 8px;font-weight:600}h2{font-size:13px;margin:0 0 8px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
.mut{color:var(--mut)}.null{color:var(--nul)}
.ftag{font:12px "Roboto Mono",monospace;color:var(--mut)}
.badge{color:#fff;background:#3a3c6e;display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:3px;border:0;font:400 12px/1 "Roboto Mono",ui-monospace,Menlo,monospace;text-transform:uppercase;white-space:nowrap}
.b-done{color:#fff;background:var(--green)}
.b-queued,.b-running,.b-retry,.b-redelivered,.b-window{color:var(--ink);background:var(--orange)}
.b-miss{color:var(--ink);background:#e5a823}
.b-failed{color:#fff;background:var(--red)}
.b-cancelled{color:#fff;background:var(--head)}
.b-critical{color:#fff;background:#9c1237}
.b-high{color:#fff;background:var(--red)}
.b-medium{color:var(--ink);background:var(--orange)}
.b-low{color:var(--ink);background:#e5c100}
.b-info{color:#fff;background:var(--bar)}
.dl{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:3px;background:var(--green);color:#fff;white-space:nowrap}
.dl:hover{background:#12b42c;text-decoration:none}
.dlbig{display:inline-block;padding:10px 20px 9px;border-radius:5px;background:var(--blue);color:#fff;line-height:1}
.dlbig:hover{background:#3a62ff;text-decoration:none}
.b-unknown{color:var(--mut);background:var(--panel2);border-color:var(--line)}
.hits{position:absolute;top:8px;right:8px;z-index:3;background:var(--green);color:#fff;border-radius:3px;padding:2px 6px;font-size:12px;line-height:1.2;pointer-events:none}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 10px}
.chip{display:inline-flex;align-items:center;height:33px;padding:0 14px;border-radius:5px;background:var(--panel2);border:1px solid transparent;color:var(--fg)}
.chip.on{background:var(--blue);border-color:var(--blue);color:#fff}.chip:hover{text-decoration:none;background:var(--head)}
.grid{overflow-x:auto}
.pv>input[type=radio]{position:absolute;opacity:0;pointer-events:none}
.pv-bar{margin:0 0 10px;justify-content:space-between}.pv-bar label.chip{cursor:pointer}
#pv-1:checked~.pv-bar label[for=pv-1],#pv-2:checked~.pv-bar label[for=pv-2]{background:var(--blue);border-color:var(--blue);color:#fff}
#pv-1:focus-visible~.pv-bar label[for=pv-1],#pv-2:focus-visible~.pv-bar label[for=pv-2]{outline:2px solid var(--info)}
.cfg-bar{margin:0 0 10px;justify-content:flex-end}
#pv-1:checked~.pv-syc,#pv-2:checked~.pv-pcap{display:none}
.pv-cap{margin:0 0 8px}
table{border-collapse:collapse;width:100%;min-width:760px}
th{background:var(--head);color:#fff;text-align:left;font-weight:400;font-size:12px;height:40px;padding:0 10px;white-space:nowrap;border-left:1px solid var(--hsep);border-bottom:1px solid var(--hline)}
td{padding:8px 10px;font-size:12px;border-top:1px solid var(--line);border-left:1px solid var(--line);vertical-align:top;background:var(--row)}
th:first-child,td:first-child{border-left:0}
tr:hover td{background:var(--hover)}
.tpk{display:flex;align-items:center;height:36px;padding:0 4px 0 2px;border-radius:5px;background:var(--panel2)}
.tpk .dd.tlr>summary{height:36px;gap:8px;padding:0 8px;background:none;border:0}.tpk .dd.tlr>summary:hover{background:var(--head)}
.tpk .cal{color:#fff;flex:none}.tld{display:flex;flex-direction:column;font-size:13px;line-height:15px;letter-spacing:.2px}
.tclr{display:flex;align-items:center;justify-content:center;width:24px;height:24px;color:#e9ebf3;font-size:18px}.tclr:hover{color:#fff;text-decoration:none}
.dd.tlr .mi.off{opacity:.35;pointer-events:none}
.tcus{display:flex;flex-direction:column;gap:8px;padding:4px 10px 8px}.tcus label{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--mut)}
.tcus input{color-scheme:dark}
.toast{position:fixed;top:60px;right:20px;z-index:60;display:flex;align-items:center;gap:10px;max-width:460px;padding:12px 14px;border-radius:5px;background:var(--panel2);border-left:4px solid var(--green);box-shadow:0 6px 24px #000a;transition:opacity .3s}
.toast.out{opacity:0}.toast .tk{color:var(--green)}.toast .tx{margin-left:auto;background:none;border:0;color:var(--mut);font-size:18px;cursor:pointer}.toast .tx:hover{color:#fff}
.c-kb{justify-content:center;padding:0!important}.kb{width:28px;height:26px;border:0;border-radius:4px;background:none;color:#e9ebf3;font-size:18px;line-height:1;cursor:pointer}.kb:hover{background:var(--head)}
.kmenu{position:fixed;z-index:65;min-width:190px}.kmenu[hidden]{display:none}
.rxb{display:inline-flex;align-items:center;height:16px;margin-left:6px;padding:0 5px;border-radius:3px;background:#3a3c6e;color:#dadce6;font-size:10px;flex:none}
dialog.modal{width:min(680px,94vw);padding:0;border:0;border-radius:5px;background:var(--panel);color:var(--fg);box-shadow:0 12px 48px #000c}
dialog.modal::backdrop{background:rgba(6,7,37,.72)}
.modal .mh{display:flex;align-items:center;justify-content:space-between;padding:16px 20px 0}.modal .mh .ct{margin:0}
.modal .tx{background:none;border:0;color:var(--mut);font-size:20px;cursor:pointer}.modal .tx:hover{color:#fff}
.modal .mb{padding:4px 20px 8px;max-height:70vh;overflow:auto}.modal h4{margin:16px 0 8px;font-size:14px;font-weight:500}
.modal .mf{display:flex;justify-content:flex-end;gap:10px;padding:14px 20px;border-top:1px solid var(--line)}
.rxrow{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px;margin:8px 0}.rxrow label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--mut)}
.rxrow input[type=number]{width:120px}.rxq{display:flex;gap:6px}.rxq button,.lnk{background:var(--panel2);border:0;border-radius:5px;color:var(--fg);padding:6px 10px;font-size:12px;cursor:pointer}.rxq button:hover,.lnk:hover{background:var(--head)}
.rxr{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:13px}.rxr code{color:var(--mut)}
.rxh{display:flex;gap:8px;align-items:center;margin:6px 0}.rxh input{flex:1}
.rxp{padding:10px 12px;border-radius:5px;background:var(--panel2);font:12px/1.6 "Roboto Mono",monospace;overflow-wrap:anywhere}.rxp.bad{color:#ff8b98}.rxp .warn{font-family:inherit}
.btn-pri{background:var(--blue);color:#fff;border:0;border-radius:5px;padding:9px 18px;cursor:pointer}.btn-pri:hover{background:#3a62ff}.btn-pri:disabled{background:#1a318e;color:#9899b3;cursor:default}
.btn-sec{background:var(--panel2);color:#fff;border:0;border-radius:5px;padding:9px 18px;cursor:pointer}.btn-sec:hover{background:var(--head)}
.fchips{display:flex;flex-wrap:wrap;gap:6px}.fchip{display:inline-flex;align-items:center;height:33px;border-radius:5px;background:var(--blue);color:#fff;font-size:12px;line-height:1.1;overflow:hidden}
.fchip .fced{display:flex;align-items:center;height:100%;padding:0;border:0;background:none;color:#fff;font:inherit;cursor:pointer}.fchip .fced:hover{background:var(--blue2)}
.fadd{width:33px;height:33px;border:0;border-radius:5px;background:var(--panel2);color:#fff;font-size:20px;line-height:1;cursor:pointer}.fadd:hover{background:var(--head)}
.fpop{position:fixed;z-index:66;width:340px;display:flex;flex-direction:column;gap:10px;padding:16px;border-radius:5px;background:#090a30;border:1px solid var(--pop);box-shadow:0 10px 36px #000c}.fpop[hidden]{display:none}
.fpop select,.fpop input[type=text]{width:100%;height:36px}.fp-n{font-size:12px;color:var(--mut);text-align:right}
.fp-list{flex:1 1 auto;min-height:60px;max-height:300px;overflow:auto;display:flex;flex-direction:column;gap:2px}
.fp-it{display:grid;grid-template-columns:22px 1fr auto;align-items:center;gap:4px 10px;padding:6px 6px;border-radius:4px;cursor:pointer}.fp-it:hover{background:var(--panel)}
.fp-it .bar{grid-column:2/4;height:4px;border-radius:2px;background:#1c1d3b}.fp-it .bar i{display:block;height:100%;border-radius:2px;background:var(--blue)}
.fp-it span.v{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.fp-it span.p{font-size:12px;color:var(--mut)}
.fp-foot{display:flex;justify-content:flex-end;gap:10px;border-top:1px solid var(--line);padding-top:12px}
.fchip .fk{padding:0 6px 0 10px;opacity:.85}.fchip .fvv{padding:0 4px;font-family:"Roboto Mono",monospace}.fchip a{display:flex;align-items:center;height:100%;padding:0 9px;color:#fff;font-size:16px}.fchip a:hover{background:var(--blue2);text-decoration:none}
a.fv{color:inherit}a.fv:hover{text-decoration:underline dotted}
.acts{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:4px 0 12px}
.bact{display:inline-flex;align-items:center;height:33px;padding:0 16px;border:0;border-radius:5px;background:var(--blue);color:#fff;font:inherit;font-size:13px;line-height:1;white-space:nowrap;cursor:pointer}
.bact:hover{background:#3a62ff;text-decoration:none}.bact.red{background:var(--red)}.bact.red:hover{background:#f02a43}
.chiprow{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}.chiprow .chips{flex:1;margin:0}
.tlctl{display:flex;align-items:center;gap:8px}.dd.tlr .ddp{left:auto;right:0;min-width:240px}.dd.tlr .mi b{display:inline-block;width:34px;font-weight:400;font-family:"Roboto Mono",monospace;font-size:12px;color:var(--mut)}
.dd.tlr>summary{gap:10px}.tlp{display:inline-flex;align-items:center;height:20px;padding:0 6px;border-radius:3px;background:#d3dae6;color:var(--panel);font:12px/1 "Roboto Mono",monospace}.tls{font-size:12px;line-height:1.15}
.tlbtn{display:inline-flex;align-items:center;justify-content:center;width:33px;height:33px;border-radius:5px;background:var(--panel2);color:var(--fg);font-size:18px}.tlbtn:hover{background:var(--head);text-decoration:none}
.tlnav.off,.tlbtn.off{opacity:.3;cursor:default}
.tl{flex-basis:100%;display:flex;align-items:stretch;height:190px;margin-top:14px}
.tlnav{flex:none;width:26px;display:flex;align-items:center;justify-content:center;color:var(--mut);font-size:28px;line-height:1}.tlnav:hover{color:#fff;text-decoration:none}
.tly{flex:none;width:44px;position:relative}.tlyl{position:absolute;left:0;top:50%;transform:translateY(-50%) rotate(180deg);writing-mode:vertical-rl;font-size:12px;color:var(--mut)}
.tlp2{flex:1;position:relative;border-bottom:1px solid var(--hline);cursor:crosshair;user-select:none}
.tlg i{position:absolute;left:0;right:0;font-style:normal;border-top:1px solid rgba(255,255,255,.08)}.tlg b{position:absolute;right:100%;margin-right:8px;transform:translateY(-50%);font-weight:400;font-size:11px;color:var(--mut)}
.tlb{position:absolute;inset:0;display:flex;align-items:flex-end;gap:2px}.tlb div{flex:1;background:var(--bar)}.tlb div:hover{background:#4a8af0}.tlb div.z{background:transparent}
.brush{position:absolute;top:0;bottom:0;display:none;background:rgba(15,139,253,.2);border:1px solid var(--info);pointer-events:none}
.tlx{flex-basis:100%;position:relative;height:18px;margin:5px 26px 0 70px}.tlx span{position:absolute;transform:translateX(-50%);font-size:11px;color:var(--mut);white-space:nowrap}
.tlcap{flex-basis:100%;font-size:11px;margin-top:2px}
.jhead>span[draggable=true]{cursor:grab}.jhead>span.drag{opacity:.45}.jhead>span.dropl{box-shadow:inset 3px 0 var(--info)}.jhead>span.dropr{box-shadow:inset -3px 0 var(--info)}
.msg{margin:6px 0 0;font-size:14px}.warn{color:var(--warn)}
.jobs{overflow:auto;max-height:calc(100vh - 150px);min-height:240px}
.jhead{position:sticky;top:0;z-index:6}
.jhead,.job summary{display:grid;grid-template-columns:var(--cols);gap:0;align-items:stretch;min-width:var(--minw);padding:0}
.jhead>span,.job summary>span{position:relative;display:flex;align-items:center;min-width:0;min-height:30px;padding:0 10px;border-left:1px solid var(--line);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.job summary>span>.ell{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.jhead>span:first-child,.job summary>span:first-child{border-left:0}
.jhead{background:var(--head);color:#fff;border-bottom:1px solid var(--hline)}.jhead>span{flex-direction:column;justify-content:center;align-items:flex-start;min-height:48px;padding:5px 10px;border-left-color:var(--hsep);overflow:visible}
.jhead .hl{display:block;font-weight:400;font-size:13px;line-height:17px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}.jhead .fld{display:block;font-size:11px;line-height:14px;color:#dadce6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.rsz{position:absolute;top:0;right:-4px;width:8px;height:100%;cursor:col-resize;z-index:2}.rsz:hover,.rsz.on{background:linear-gradient(90deg,transparent 3px,var(--info) 3px,var(--info) 5px,transparent 5px)}
body.resizing{cursor:col-resize;user-select:none}
.jhead a{color:inherit}.jhead a:hover{text-decoration:underline}.jhead .arr{color:var(--info);font-size:10px}
.jhead>span.c-sel,.job summary>span.c-sel{flex-direction:row;align-items:center;justify-content:flex-start;gap:8px;padding-left:12px}
.fpop input[type=checkbox]{width:20px!important;height:20px!important}
.jobs input[type=checkbox],.dd input[type=checkbox],.selbar input[type=checkbox],.fpop input[type=checkbox]{-webkit-appearance:none;appearance:none;width:20px;height:20px;border:2px solid rgba(255,255,255,.2);border-radius:5px;background:var(--panel2);cursor:pointer;position:relative;flex:none;margin:0}
.jobs input[type=checkbox]:checked,.dd input[type=checkbox]:checked,.selbar input[type=checkbox]:checked,.fpop input[type=checkbox]:checked{background:var(--blue);border-color:var(--blue)}
.jobs input[type=checkbox]:checked::after,.dd input[type=checkbox]:checked::after,.selbar input[type=checkbox]:checked::after,.fpop input[type=checkbox]:checked::after{content:"";position:absolute;left:5px;top:1px;width:4px;height:9px;border:solid #fff;border-width:0 2px 2px 0;transform:rotate(45deg)}
.dd input[type=checkbox]:disabled{opacity:.5;cursor:default}
.tools{display:flex;align-items:center;gap:12px;margin:0 0 10px;flex-wrap:wrap}.tools .sp{flex:1}
.dd{position:relative}
.dd>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;height:33px;padding:0 12px;border:1px solid transparent;border-radius:5px;background:var(--panel2);color:var(--fg);font-size:14px;white-space:nowrap}
.dd>summary::-webkit-details-marker{display:none}.dd>summary:hover{background:var(--head)}
.dd.act>summary{background:#1a318e;color:#9899b3;gap:0;padding:0}.dd.act>summary .al{padding:0 20px 0 22px}.dd.act>summary .chev{box-sizing:content-box;padding:0 12px;border-left:1px solid #112473;height:33px;background:#18287d;border-radius:0 5px 5px 0}
.dd.act>summary.on{background:var(--blue);color:#fff}.dd.act>summary.on .chev{background:var(--blue2);border-left-color:#1a26a8}
.chev{flex:none;opacity:.85}
.ddp{position:absolute;left:0;top:36px;z-index:30;min-width:200px;max-height:70vh;overflow:auto;display:flex;flex-direction:column;background:var(--panel2);border:1px solid var(--pop);border-radius:5px;padding:6px;box-shadow:0 6px 24px #0008}
.dd.cols .ddp,.dd.views .ddp,.dd.gear .ddp{left:auto;right:0}
.mi{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:4px;color:var(--fg);background:none;border:0;font:inherit;text-align:left;cursor:pointer;white-space:nowrap}
.mi:hover{background:var(--head);text-decoration:none}.mi:disabled{color:var(--mut);cursor:default;background:none}
.mi.del:not(:disabled){color:#ff7b86}.mi.cur{font-weight:700;cursor:default}
.gh{padding:6px 10px 2px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--mut)}
.vrow{justify-content:space-between}.vrow a{color:var(--fg);flex:1}
.vx{background:none;border:0;color:var(--mut);cursor:pointer;font-size:16px;line-height:1}.vx:hover{color:var(--bad)}
.srch{position:relative;display:flex;align-items:center;margin:0}.srch .lupa{position:absolute;left:12px;width:18px;height:18px;color:var(--mut);pointer-events:none}
.srch input[type=search]{height:33px;width:236px;padding:0 30px 0 40px;border:1px solid transparent;border-radius:5px;background:var(--panel2);color:var(--fg);font:inherit;font-size:14px}.srch input::placeholder{color:var(--mut)}
.srch input[type=search]:focus{outline:0;border-color:var(--info)}.srch input[type=search]::-webkit-search-cancel-button{display:none}
.srch .clr{position:absolute;right:9px;color:var(--mut);font-size:16px;line-height:1}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.dd.gear>summary{width:33px;padding:0;justify-content:center;color:#e9ebf3}
.selbar{display:flex;align-items:center;gap:14px;padding:6px 12px;margin:0 0 8px;background:var(--panel2);border:1px solid var(--line);border-radius:5px}
.selbar[hidden]{display:none}
.job:has(.row-chk:checked){background:linear-gradient(0deg,rgba(15,139,253,.25),rgba(15,139,253,.25)),var(--row)}
.job{border-bottom:1px solid var(--line);background:var(--row)}
.job summary{cursor:pointer;list-style:none}.job summary::-webkit-details-marker{display:none}
.job summary:hover{background:var(--hover)}.job[open]>summary{background:var(--hover)}
.caret{flex:none;width:0;height:0;border-left:6px solid var(--mut);border-top:5px solid transparent;border-bottom:5px solid transparent;transition:transform .1s}
.job[open] .caret{transform:rotate(90deg);border-left-color:var(--info)}
.more{padding:10px 14px 14px 36px;border-top:1px solid var(--line);background:var(--panel)}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:8px 18px;margin:0 0 12px}
.more h3{font-size:12px;margin:10px 0 6px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
.nm{font-weight:400}
.kv>.desc{min-width:0}.kv>.desc[open]{grid-column:1/-1}
.desc>summary,.job .desc>summary{display:block;min-width:0;padding:0;background:none!important;cursor:pointer;list-style:none;font-size:12px;color:var(--mut)}
.desc>summary::-webkit-details-marker{display:none}.desc>summary::before{content:"\\25B8";display:inline-block;width:14px;color:var(--info)}.desc[open]>summary::before{content:"\\25BE"}
.desc>summary:hover{color:var(--info)}.desc p{margin:6px 0 0;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere;max-width:110ch;color:var(--fg);text-transform:none;letter-spacing:0;font-size:13px}
.kv .mut{display:block;font-size:12px}
.kv code{overflow-wrap:anywhere}.empty{padding:14px;color:var(--mut)}
.sel-count{color:var(--mut);font-size:12px}
.sel-opt{font-size:12px;color:var(--mut);display:flex;align-items:center;gap:4px;cursor:pointer}
.btn-del{background:var(--red);color:#fff;border:0;border-radius:5px;padding:7px 14px;font-size:12px;cursor:pointer}
.btn-del:hover{background:#f02a43}
input[type=file]{color:var(--mut)}input[type=file]::file-selector-button{background:var(--panel2);color:var(--fg);border:0;border-radius:5px;padding:6px 12px;margin-right:8px;cursor:pointer}input[type=file]::file-selector-button:hover{background:var(--head)}
input[type=text],input[type=password],input[type=number],select,textarea{background:var(--panel2);color:var(--fg);border:1px solid transparent;border-radius:5px;padding:6px 8px;font:inherit}
input[type=text]:focus,input[type=password]:focus,input[type=number]:focus,select:focus,textarea:focus{outline:0;border-color:var(--info)}
.star-f{display:inline;margin:0;padding:0}
.star-btn{background:none;border:0;color:var(--mut);font-size:14px;cursor:pointer;padding:0 3px;line-height:1;vertical-align:middle}
.star-btn:hover,.star-btn.on{color:#ffd700}
.b-persistent{color:#ffd700;background:#423812;border-color:#8a7522}
.pbar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;padding:10px 4px 0;font-size:12px;color:var(--mut)}.pbar .recs{margin-left:auto;color:var(--info)}
.pbar a{padding:2px 8px;border-radius:5px;border:1px solid var(--line);background:var(--panel2);color:var(--fg)}
.pbar a.on{background:var(--blue);border-color:var(--blue);color:#fff}
.pbar a:hover{text-decoration:none;border-color:var(--info)}
.pbar .dim{color:var(--nul);padding:2px 8px}
.pbar .sizes{display:flex;align-items:center;gap:6px}
.pbar .pages{display:flex;align-items:center;gap:4px}
.ptitle{font-size:22px;font-weight:400;margin:2px 0 14px}
.ct{font-size:17px;font-weight:500;margin:0 0 14px;color:#fff;text-transform:none;letter-spacing:0}
.cth{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.cth .ct{margin:0}
.srow{display:grid;grid-template-columns:1.6fr 1fr 1.6fr;gap:8px;margin-bottom:8px}.srow .card{margin:0}
.st{font:12px "Roboto Mono",monospace;white-space:nowrap}.st-ok{color:var(--green)}.st-warn{color:var(--orange)}.st-fail{color:var(--red)}.st-unk{color:var(--nul)}
.tiles{display:flex;align-items:flex-start;justify-content:center;gap:10px;margin-top:6px}.tiles em{font-style:normal;color:var(--mut);margin-top:12px}
.tiles div{display:flex;flex-direction:column;align-items:center;gap:8px}.tiles b{display:inline-flex;align-items:center;justify-content:center;min-width:42px;height:42px;padding:0 6px;border-radius:3px;background:var(--green);font-weight:400;font-size:24px}
.tiles span{font-size:12px;color:var(--fg)}.tilecap{text-align:center;margin-top:12px;font-size:12px}
.res{display:grid;grid-template-columns:1fr 48px;align-items:center;gap:6px 12px;margin-bottom:14px}.res h4{grid-column:1/-1;margin:0;font-size:14px;font-weight:500}
.rd{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;background:var(--blue)}.rd.m{background:#6f7fa8}.rd.c{background:#00bff8}
.rp{text-align:right;font-size:13px}
.ubar{height:8px;border-radius:4px;background:#1c1d3b}.ubar i{display:block;height:100%;background:var(--blue);border-radius:4px}.ubar i.mid{background:var(--orange)}.ubar i.hi{background:var(--red)}
.utext{display:flex;justify-content:space-between;gap:12px;margin-top:6px;font-size:12px}.utext b{font-weight:600}
.dtab td{vertical-align:middle;padding:10px}.dtab td:nth-child(3){width:70px;text-align:right}.upct{font-size:18px}.dline{display:block;font-size:12px}
.ubar{position:relative}.umark{position:absolute;top:-3px;width:2px;height:14px;background:var(--red)}
.idl{display:block;color:var(--mut);font-size:11px}
@media (max-width:1100px){.srow{grid-template-columns:1fr}}
@media (max-width:640px){.wrap{padding:12px 8px}td,th{padding:5px 6px}}
"""



def _font_face(family: str, file: str, weight: str) -> str:
    """An @font-face with the woff2 inline: the pages need no extra route (Passthrough, allowlists)."""
    path = Path(__file__).with_name("fonts") / file
    try:
        data = base64.b64encode(path.read_bytes()).decode()
    except OSError:  # a missing file only loses the font, the fallback stack takes over
        return ""
    return (f'@font-face{{font-family:"{family}";src:url(data:font/woff2;base64,{data}) format("woff2");'
            f"font-weight:{weight};font-style:normal;font-display:swap}}")


# Sycope's own fonts (OFL, see fonts/README.txt), so the pages render like its UI.
_FONT_CSS = _font_face("Kumbh Sans", "KumbhSans.woff2", "400 600") + _font_face("Roboto Mono", "RobotoMono.woff2", "400")

_PENDING = (QUEUED, RUNNING)


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _cell(value: object) -> str:
    """Table cell text; empty values look like Sycope's <null>."""
    text = "" if value is None else str(value)
    return _e(text) if text != "" else '<span class="null">&lt;null&gt;</span>'


def _t(epoch: float | None) -> str:
    if not epoch:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch))


def _ts(epoch: float | None, fmt: str = "dt") -> str:
    """A time cell. The text is UTC (no JavaScript); `_TZ_JS` rewrites it into the viewer's zone."""
    if not epoch:
        return '<span class="null">&lt;null&gt;</span>'
    pattern = {"hm": "%H:%M", "dhm": "%m-%d %H:%M", "d": "%Y-%m-%d"}.get(fmt, "%Y-%m-%d %H:%M:%S")
    text = time.strftime(pattern, time.gmtime(epoch))
    return f'<time class="ts" data-e="{int(epoch)}" data-f="{fmt}">{text}</time>'


_RF_PANEL = (
    '<details class="rfd"><summary title="Auto refresh" aria-label="Auto refresh">'
    '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 6l5 5 5-5" fill="none" '
    'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></summary>'
    '<div class="rfp"><label class="sw"><input type="checkbox" id="rf-on"><span></span></label>'
    '<label for="rf-on">Refresh every full</label>'
    '<input type="number" id="rf-n" min="1" max="999" value="30">'
    '<select id="rf-u"><option value="1">Second(s)</option><option value="60">Minute(s)</option></select>'
    '<span class="rfst" id="rf-st"></span></div></details>')

# Auto refresh: the choice (on/off, number, unit) is kept per browser; the default is the page's own
# interval, on or off as the page says (data-rfon). It fires on a full interval boundary (like Sycope's
# "Refresh every full") and waits while the operator is in the middle of something: rows ticked, a
# dialog (re-extract) or a menu open, a field focused. The rows that were expanded stay expanded across
# the reload (and the scroll position): kept in sessionStorage for this URL only.
_RF_JS = (
    '<script>(function(){var b=document.body,K="srRefresh",O="srOpen",def=+b.dataset.rf||0,t=null,'
    'on=document.getElementById("rf-on"),n=document.getElementById("rf-n"),u=document.getElementById("rf-u"),'
    'st=document.getElementById("rf-st");'
    'try{var k=JSON.parse(sessionStorage.getItem(O));sessionStorage.removeItem(O);if(k&&k.u===location.href){'
    'document.querySelectorAll("details.job[data-id]").forEach(function(d){d.open=k.ids.indexOf(d.dataset.id)>=0});'
    'window.scrollTo(0,k.y||0)}}catch(e){}'
    'if(!on)return;'
    'var c={on:def>0&&b.dataset.rfon!=="0",n:def>=60&&def%60==0?def/60:(def||30),u:def>=60&&def%60==0?60:1};'
    'try{var v=JSON.parse(localStorage.getItem(K));if(v&&typeof v.on==="boolean"){c.n=v.n;c.u=v.u;if(def)c.on=v.on}}catch(e){}'
    'on.checked=c.on;n.value=c.n;u.value=String(c.u);'
    'function save(){c={on:on.checked,n:Math.max(1,+n.value||1),u:+u.value};'
    'try{var o=JSON.parse(localStorage.getItem(K))||{};'
    'localStorage.setItem(K,JSON.stringify({on:def?c.on:(o.on!==false),n:c.n,u:c.u}))}catch(e){}arm()}'
    'function busy(){var a=document.activeElement;return document.querySelector(".row-chk:checked,'
    '#chk-all-matching:checked,dialog[open],#kmenu:not([hidden]),details.dd[open],details.rfd[open],'
    'details.menu[open]")||(a&&/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)&&a.type!=="checkbox")}'
    'function keep(){var ids=[];document.querySelectorAll("details.job[open][data-id]").forEach(function(d){'
    'ids.push(d.dataset.id)});try{sessionStorage.setItem(O,JSON.stringify({u:location.href,ids:ids,y:window.scrollY}))'
    '}catch(e){}}'
    'function arm(){clearTimeout(t);st.textContent="";if(!c.on)return;var ms=c.n*c.u*1000,'
    'w=ms-(Date.now()%ms);t=setTimeout(function(){if(busy()){arm();return}keep();location.reload()},w);'
    'st.textContent="next in "+Math.ceil(w/1000)+" s"}'
    'on.onchange=n.onchange=u.onchange=save;arm()})();</script>')


# The Sycope Passthrough answers 502 to an urlencoded form body (JSON, text and an empty body pass), so
# every POST form of ours is sent as JSON by a script and the answer (a redirect or a page) is followed.
_FORM_JS = (
    '<script>document.addEventListener("submit",function(e){var f=e.target;'
    'if(e.defaultPrevented||!f||(f.method||"").toLowerCase()!=="post"||!window.fetch||!window.FormData)return;'
    'e.preventDefault();var d={},fd;try{fd=new FormData(f,e.submitter)}catch(x){fd=new FormData(f)}'
    'fd.forEach(function(v,k){if(k in d){if(!Array.isArray(d[k]))d[k]=[d[k]];d[k].push(v)}else d[k]=v});'
    'if(typeof d.job_id==="string"&&f.querySelector(".row-chk"))d.job_id=[d.job_id];'
    'fetch((e.submitter&&e.submitter.getAttribute("formaction"))||f.getAttribute("action")||"",{method:"POST",headers:{"Content-Type":"application/json","Accept":"text/html"},'
    'body:JSON.stringify(d),credentials:"same-origin"}).then(function(r){'
    'if(r.redirected){location.href=r.url;return}'
    'var ct=r.headers.get("content-type")||"";return r.text().then(function(t){'
    'if(ct.indexOf("text/html")===0){document.open();document.write(t);document.close()}else alert(t)})})'
    '.catch(function(x){alert("Request failed: "+x)})});</script>')

_MENU_JS = (
    '<script>(function(){var q=".menu,.rfd,.dd";function all(){return document.querySelectorAll(q)}'
    'document.addEventListener("click",function(e){all().forEach(function(d){'
    'if(d.open&&!d.contains(e.target))d.open=false})});'
    'document.addEventListener("keydown",function(e){if(e.key==="Escape")all().forEach(function(d){d.open=false})});'
    'all().forEach(function(d){d.addEventListener("toggle",function(){if(d.open)all().forEach(function(o){'
    'if(o!==d)o.open=false})})})})();</script>')


_INFO_JS = (
    '<div id="tip" role="tooltip"></div><script>(function(){var t=document.getElementById("tip");'
    'function show(e,txt){var r=e.getBoundingClientRect();t.textContent=txt||e.dataset.tip;t.style.display="block";'
    'var w=t.offsetWidth,h=t.offsetHeight,x=Math.min(Math.max(8,r.left-8),innerWidth-w-8),'
    'y=r.bottom+8;if(y+h>innerHeight-8)y=Math.max(8,r.top-h-8);t.style.left=x+"px";t.style.top=y+"px"}'
    'function hide(){t.style.display="none"}'
    'document.querySelectorAll(".info").forEach(function(e){e.addEventListener("mouseenter",function(){show(e)});'
    'e.addEventListener("focus",function(){show(e)});e.addEventListener("mouseleave",hide);'
    'e.addEventListener("blur",hide);e.addEventListener("click",function(ev){ev.stopPropagation();show(e)})});'
    'document.addEventListener("click",hide);window.addEventListener("scroll",hide,true);'
    # A cut cell (.ell) shows its whole text on hover; the alert name always does (it carries the id).
    'document.addEventListener("mouseover",function(ev){var e=ev.target.closest&&ev.target.closest(".ell");'
    'if(!e||e.contains(ev.relatedTarget))return;if(e.dataset.always||e.scrollWidth>e.clientWidth+1)'
    'show(e,e.dataset.full||e.textContent)});'
    'document.addEventListener("mouseout",function(ev){var e=ev.target.closest&&ev.target.closest(".ell");'
    'if(e&&!e.contains(ev.relatedTarget))hide()})})();</script>')

_TZ_JS = (
    '<script>(function(){function p(n){return(n<10?"0":"")+n}'
    'document.querySelectorAll("time.ts").forEach(function(t){var d=new Date(+t.dataset.e*1000);'
    'var h=p(d.getHours())+":"+p(d.getMinutes());'
    'var f=t.dataset.f,md=p(d.getMonth()+1)+"-"+p(d.getDate()),ymd=d.getFullYear()+"-"+md;'
    't.textContent=f==="hm"?h:f==="dhm"?md+" "+h:f==="d"?ymd:ymd+" "+h+":"+p(d.getSeconds());'
    't.title=d.toUTCString()});'
    'var z=document.getElementById("tzname");if(z)z.textContent=Intl.DateTimeFormat().resolvedOptions().timeZone})();</script>'
)


def _size(n: int | None) -> str:
    if n is None:
        return ""
    return f"{n / 1024:.1f} KiB" if n >= 1024 else f"{n} B"


def meta_of(job: dict) -> dict:
    """The alert details stored with the job (empty for jobs created before they were kept)."""
    try:
        meta = json.loads(job.get("alert_meta") or "{}")
    except ValueError:
        return {}
    return meta if isinstance(meta, dict) else {}


def _sev(value: object) -> str:
    sev = str(value or "").lower()
    if sev in ("critical", "high", "medium", "low", "info"):
        return f'<span class="badge b-{sev}">{_e(value)}</span>'
    return _cell(value)


def _kv(label: str, value_html: str) -> str:
    return f'<div><span class="mut">{_e(label)}</span>{value_html}</div>'


def _alert_kv(job: dict) -> str:
    """The "Alert" block: name, id, time, severity, rule, MITRE, flow."""
    m = meta_of(job)
    when = m.get("alertTime")
    mitre = " / ".join(str(m[k]) for k in ("mitreTactic", "mitreTechnique") if m.get(k))
    if m.get("mitreId"):
        mitre += f" ({m['mitreId']})"
    flow = ""
    if m.get("clientIp") or m.get("serverIp"):
        flow = f"{m.get('clientIp') or '?'} \u2192 {m.get('serverIp') or '?'}"
        if m.get("serverPort"):
            flow += f":{m['serverPort']}"
        if m.get("protocol"):
            flow += f" {m['protocol']}"
    rule = " / ".join(str(m[k]) for k in ("ruleId", "ruleType") if m.get(k))
    sev = _sev(m.get("severity")) if m.get("severity") else _cell("")
    if m.get("alertFlagThresholdLevel"):
        sev += f' <span class="mut">threshold {_e(m["alertFlagThresholdLevel"])}</span>'
    items = [
        _kv("Alert name", f"<b>{_cell(m.get('name'))}</b>"),
        _kv("Alert ID", f"<code>{_e(job['alert_id'])}</code>"),
        _kv("Alert time", _ts(when) + (
            f' <span class="mut">Sycope: {_e(m["timestamp"])}</span>' if m.get("timestamp") else "")),
        _kv("Severity", sev),
        _kv("Score", _cell(m.get("score"))),
        _kv("Rule", _cell(rule)),
        _kv("MITRE ATT&CK", _cell(mitre.strip())),
        _kv("Flow", f"<code>{_cell(flow)}</code>" if flow else _cell("")),
        _kv("Rule definition", f"<code>{_e(m.get('definitionId'))}</code>" if m.get("definitionId")
            else _cell("")),
        _kv("Interval / range", _cell(" / ".join(str(m[k]) for k in ("interval", "timeRange")
                                                  if m.get(k)))),
    ]
    if m.get("profile"):
        items.append(_kv("Extraction profile", _e(m["profile"])))
    if m.get("tags"):
        items.append(_kv("Tags", _e(m["tags"])))
    desc = job.get("alert_desc")
    if desc:  # a collapsed item of its own, right after Tags; the chevron opens it
        items.append(f'<details class="desc"><summary>Description</summary><p>{_e(desc)}</p></details>')
    return f'<div class="kv">{"".join(items)}</div>'


# How an event reads in a history table where it is not the job's own state: a `reextract` event says that a
# new file was made from this job, the job itself did not change.
_EVENT_LABEL = {"reextract": "re-extracted"}


def _badge(state: str) -> str:
    return f'<span class="badge b-{_e(state)}">{_e(_EVENT_LABEL.get(state, state))}</span>'


def _menu(bundle: bool, active: str | None = None) -> str:
    """The top-bar menu: one entry per page (a download for the logs)."""
    items = [("./", "Queue", "queue"), ("system", "System status", "status"), ("profiles", "Profiles", "profiles"),
             ("configuration", "Configuration", "configuration")]
    if bundle:
        items.append(("logs", "Download debug logs", "logs"))
    links = "".join(f'<a href="{href}"{" class=\"cur\"" if key == active else ""}>{_e(label)}</a>'
                    for href, label, key in items)
    return (f'<details class="menu"><summary title="Menu" aria-label="Menu">{_gear(24)}</summary>'
            f'<div class="menup">{links}</div></details>')


# Outline icons drawn like Sycope's top bar (thin white strokes).
_REFRESH = ('<svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" '
            'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19.5 10.5A7.7 7.7 0 0 0 '
            '6 6.6L4.5 8.2"/><path d="M4.5 4v4.2h4.2"/><path d="M4.5 13.5A7.7 7.7 0 0 0 18 17.4l1.5-1.6"/>'
            '<path d="M19.5 20v-4.2h-4.2"/></svg>')
# The logo: Sycope's lettering with its triangle as the "o" of "recorder".
# Sycope's own logo (assets/layout/images/logo_sycope_dark.svg, paths unchanged) and the product name as text;
# a link to the queue ("./" against <base>, like the menu).
_LOGO = ('<a class="logo" href="./" title="Queue" aria-label="Sycope recorder: queue">'
         '<svg viewBox="0 0 491.7 127.6" aria-hidden="true"><defs><linearGradient id="lgo-g" gradientUnits="userSpaceO'
         'nUse" x1="213.056" y1="58.1443" x2="314.8241" y2="58.1443"><stop offset="0" stop-color="#00C1F8"/><stop offs'
         'et="1" stop-color="#143DFB"/></linearGradient></defs><path fill="url(#lgo-g)" d="M290.3,4.1L221.2,44c-10.9,6'
         '.3-10.9,22,0,28.3l69.1,39.9c10.9,6.3,24.5-1.6,24.5-14.1V18.2 C314.8,5.7,301.2-2.2,290.3,4.1z M275.6,83.6C261'
         '.5,83.6,250,72.1,250,58c0-14.1,11.4-25.5,25.5-25.5c14.1,0,25.5,11.4,25.5,25.5 C301.1,72.1,289.7,83.6,275.6,8'
         '3.6z"/><path fill="#fff" d="M48.9,95.3H3.1V81.7h45.8c3.7,0,6.7-3,6.7-6.7c0-3.1-2.1-5.8-5.1-6.5L18,60.6C8.8,5'
         '8.4,2.4,50.3,2.4,40.8 v-0.3c0-11.2,9.1-20.3,20.3-20.3h41.2v13.6H22.7c-3.7,0-6.7,3-6.7,6.7v0.3c0,3.1,2.1,5.8,'
         '5.1,6.5l32.5,7.8 c9.2,2.2,15.6,10.3,15.6,19.8C69.2,86.2,60.1,95.3,48.9,95.3z"/><path fill="#fff" d="M364.9,1'
         '8.7c-9.9,0-18.7,4.2-25.6,10.5V21h-13.6v103.3h13.6V88c6.9,5.9,15.8,9.4,25.6,9.4 c21.7,0,39.4-17.6,39.4-39.4C4'
         '04.3,36.3,386.7,18.7,364.9,18.7z M364.9,83.6c-14.1,0-25.5-11.4-25.5-25.5 c0-14.1,11.4-25.5,25.5-25.5c14.1,0,'
         '25.5,11.4,25.5,25.5C390.5,72.1,379,83.6,364.9,83.6z"/><path fill="#fff" d="M490.4,60.1c0-0.7,0.1-1.4,0.1-2.1'
         'c0-24.2-15.9-39.4-37.7-39.4c-21.7,0-39.4,17.6-39.4,39.4 c0,21.7,17.6,39.4,39.4,39.4c14.5,0,27.2-7.9,34-19.6l'
         '-11.4-7.2c-4.3,7.3-13,12.9-22.6,12.9c-13.4,0-24.4-10.3-25.4-23.4 L490.4,60.1z M452.7,31.2c11.1,0,20.5,7.8,24'
         ',18h-48C432.3,39,441.7,31.2,452.7,31.2z"/><path fill="#fff" d="M135.9,20.3l-22.5,55.2L90.8,20.3H75.1l30.4,74'
         '.6l-0.1,0.1c-3.8,9.4-12.9,15.5-23,15.5v13.9 c15.8,0,29.9-9.5,35.9-24.1l32.6-80H135.9z"/><path fill="#fff" d='
         '"M190.7,83.6c-14.1,0-25.5-11.4-25.5-25.5s11.4-25.5,25.5-25.5c6.9,0,13.1,2.7,17.7,7.2l12.3-7.1 c-7.2-8.5-18-1'
         '3.9-30.1-13.9c-21.7,0-39.4,17.6-39.4,39.4s17.6,39.4,39.4,39.4c12,0,22.7-5.4,30-13.8l-12.3-7.1 C203.8,80.8,19'
         '7.6,83.6,190.7,83.6z"/></svg>'
         '<span class="lname">recorder</span></a>')


_CAL = ('<svg class="cal" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" '
        'stroke-width="1.6" stroke-linecap="round"><rect x="3.5" y="5" width="17" height="15" rx="2"/>'
        '<path d="M3.5 10h17M8 3v4M16 3v4"/><circle cx="16" cy="15.5" r="2.6"/><path d="M16 14.3v1.3l.9.6"/></svg>')


def _toast(msg: str | None) -> str:
    """The outcome of an action as a Sycope-like toast (top right, closes itself); empty without one."""
    if not msg:
        return ""
    return (f'<div class="toast" role="status"><span class="tk">&#10003;</span><span>{_e(msg)}</span>'
            '<button type="button" class="tx" aria-label="Close">&times;</button></div>')


# The toast closes after a while and ?msg= leaves the address, so a reload does not show it again.
_TOAST_JS = (
    '<script>(function(){var t=document.querySelector(".toast");if(!t)return;function x(){t.classList.add("out");'
    'setTimeout(function(){t.remove()},300)}t.querySelector(".tx").onclick=x;setTimeout(x,7000);'
    'try{var u=new URL(location.href);if(u.searchParams.has("msg")){u.searchParams.delete("msg");'
    'history.replaceState(null,"",u.toString())}}catch(e){}})();</script>')


def _gear(px: int) -> str:
    return (f'<svg width="{px}" height="{px}" viewBox="0 0 24 24" aria-hidden="true" fill="none" '
            'stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">'
            '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 '
            '2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 '
            '9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 '
            '0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 '
            '2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 '
            '1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 '
            '1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>')


def _page(title: str, body: str, refresh: int | None = None, sub: str = "",
          base_href: str | None = None, params: dict[str, str] | None = None,
          bundle: bool = False, active: str | None = None, topctl: str = "",
          refresh_on: bool = True, auto_refresh: bool = True) -> str:
    """`topctl` goes into the top bar before the refresh button (the queue's time range). `base_href` pins relative links to the canonical (e.g. Sycope Passthrough) address, so
    they also work when the page was opened without the trailing slash. `refresh` is the page's auto refresh
    interval, `refresh_on` whether it runs before the viewer has chosen; `auto_refresh=False` leaves the
    auto refresh out of the page (a page with forms being edited), only the reload button stays."""
    # Without JavaScript the page keeps the fixed meta refresh; with it, _RF_JS owns the interval.
    meta = (f'<noscript><meta http-equiv="refresh" content="{refresh}"></noscript>'
            if refresh and refresh_on and auto_refresh else "")
    if base_href:
        meta += f'<base href="{_e(base_href.rstrip("/"))}/">'
    # Refresh = a GET form with no action: it reloads this very page (the document URL, not the
    # <base>) and the hidden fields keep the current filters (?state=, ?open=, ?view=, ...).
    hidden = "".join(f'<input type="hidden" name="{_e(k)}" value="{_e(v)}">'
                     for k, v in (params or {}).items())
    refresh_btn = (f'<form class="rf" method="get">{hidden}<button type="submit" '
                   f'title="Reload this page now" aria-label="Refresh">{_REFRESH}</button></form>')
    top = (f'<div class="top">{_LOGO}'
           f'<span class="sub">{_e(sub)}</span><span class="sp"></span>'
           + (topctl or f'<span class="mut">as of {_ts(time.time(), "hm")} <span id="tzname">UTC</span></span>')
           + f'<span class="rfg">{refresh_btn}{_RF_PANEL if auto_refresh else ""}</span>'
           f'{_menu(bundle, active)}</div>')
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">{meta}'
            f"<title>{_e(title)}</title><style>{_FONT_CSS}{_CSS}</style></head>"
            f'<body data-rf="{refresh or 0}" data-rfon="{1 if refresh_on else 0}">{top}<div class="wrap">{body}</div>{_TZ_JS}{_RF_JS}{_INFO_JS}{_FORM_JS}{_MENU_JS}{_TOAST_JS}</body></html>')


def overall_state(jobs: list[dict]) -> str:
    """One word for the alert: done if any job has a PCAP, else the newest job's state."""
    if any(j["state"] == DONE for j in jobs):
        return DONE
    return jobs[0]["state"] if jobs else "unknown"


def _info(tip: str) -> str:
    """The small (i): the text shows in a popup on hover, focus or tap (see _INFO_JS)."""
    return f' <span class="info" tabindex="0" role="note" aria-label="{_e(tip)}" data-tip="{_e(tip)}">i</span>'


def _grid(head: list, rows: list[list[str]]) -> str:
    """Header items are plain labels or (label, explanation) pairs, which get the (i)."""
    th = "".join(f"<th>{_e(h[0])}{_info(h[1])}</th>" if isinstance(h, tuple) else f"<th>{_e(h)}</th>"
                 for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="grid"><table><tr>{th}</tr>{tr}</table></div>'


def alert_page(key: str, jobs: list[dict], events: dict[str, list[dict]],
               base_href: str | None = None, pcap: tuple[str, int] | None = None,
               params: dict[str, str] | None = None) -> str:
    """Status page of one alert. `pcap` = (file name, bytes) when the file is on disk.
    `msg` is HTML (it may hold a <time> from _ts): escape anything variable that goes into it."""
    state = overall_state(jobs)
    pending = state in _PENDING
    if pcap:
        msg = "The PCAP is ready."
    elif state == DONE:
        msg = "The PCAP was extracted but the file is no longer on disk."
    elif state == MISS:
        msg = ("The recording was searched but no packets matched this alert&#39;s flow in the "
               "time window. There is nothing to download.")
    elif state == FAILED:
        msg = "Extraction failed on every attempt; see the history below."
    elif state == CANCELLED:
        msg = "An operator cancelled this extraction. Nothing to download."
    elif pending:
        msg = ("The PCAP is being prepared. The traffic window must be fully recorded first; "
               f"next attempt due after {_ts(jobs[0]['next_at'])}. This page reloads itself.")
        if str(jobs[0]["detail"]).startswith("waiting:"):
            msg += " " + _e(jobs[0]["detail"])
    else:
        msg = "Unknown state."
    done_n = sum(1 for j in jobs if j["state"] == DONE)
    button = (f'<p><a class="dlbig" href="{_e(key)}?download=1" title="Download {_e(pcap[0])}">'
              f"Download PCAP ({_e(_size(pcap[1]))})</a> <span class=\"mut\" style=\"margin-left:10px\">"
              f'<code>{_e(pcap[0])}</code>'
              + (f", the newest of {done_n} files (each is in the Jobs table below)" if done_n > 1 else "")
              + "</span></p>") if pcap else ""
    warning = next((j["detail"] for j in jobs
                    if j["state"] == DONE and str(j["detail"]).startswith("warning:")), "")
    warn = f'<div class="msg warn">{_e(warning)}</div>' if warning else ""
    head = (f'<div class="card s-{_e(state)}"><h1>PCAP for alert <code>{_e(key)}</code> '
            f'{_badge(state)}</h1><div class="msg">{msg}</div>{warn}{button}</div>')
    jobs_grid = _grid(
        ["File", "State", "Attempts", "Window (server time)", "Due after", "Updated", "Detail"],
        [[(f'<a href="{_e(_job_dl(j))}"><code>{_e(j["id"])}</code></a>' if j["state"] == DONE
           else f"<code>{_e(j['id'])}</code>")
          + (' <span class="rxb">re-extract</span>' if j.get("origin") == "operator" else ""),
          _badge(j["state"]), _cell(j["attempts"]),
          f"{_e(j['window_begin'])} to {_e(j['window_end'])}", _ts(j["ready_at"]),
          _ts(j["updated"]), _cell(j["detail"])] for j in jobs])
    evs = sorted(((ev, j) for j in jobs for ev in events.get(j["id"], [])),
                 key=lambda p: (p[0]["ts"], p[0].get("id") or 0))
    many = len(jobs) > 1
    hist_rows = [([_ts(ev["ts"])] + ([_file_tag(j)] if many else [])
                  + [_badge(ev["state"]), _cell(ev["attempt"]), _cell(_size(ev["bytes"])), _cell(ev["detail"])])
                 for ev, j in evs]
    hist_grid = _grid(["Time"] + (["File"] if many else []) + ["Event", "Attempt", "Size", "Detail"], hist_rows)
    body = (head + f'<div class="card"><h2>Alert</h2>{_alert_kv(jobs[0])}</div>'
            f'<div class="card"><h2>Jobs</h2>{jobs_grid}</div>'
            f'<div class="card"><h2>History</h2>{hist_grid}</div>')
    return _page(f"PCAP {key}", body, refresh=15 if pending else None,
                 sub="PCAP status", base_href=base_href, params=params)


_STEPS = (60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800, 1209600)
_MAX_BARS = 60
_PRESETS = (("15m", "Last 15 minutes"), ("1h", "Last hour"), ("6h", "Last 6 hours"), ("24h", "Last 24 hours"),
            ("7d", "Last 7 days"), ("30d", "Last 30 days"))


def _file_tag(j: dict) -> str:
    """Short name of a job's file next to its events: "original" or the re-extract suffix ("r2")."""
    m = re.search(r"_(r\d+)\.pcap$", str(j["id"]))
    return f'<span class="ftag" title="{_e(j["id"])}">{m.group(1) if m else "original"}</span>'


def timeline_span(window: tuple[int, int] | None, bounds: tuple[float, float] | None,
                  now: float) -> tuple[int, int, int]:
    """(start, step, n) of the timeline buckets: the window, else all jobs up to now, else 15 minutes.
    The bucket length is the first of _STEPS that keeps the bars at _MAX_BARS or fewer."""
    a: float
    b: float
    if window:
        a, b = window
    elif bounds:
        a, b = bounds[0], max(bounds[1], now)
    else:
        a, b = now - 900, now
    span = max(60.0, b - a)
    step = next((st for st in _STEPS if span / st <= _MAX_BARS), _STEPS[-1])
    start = int(a // step) * step
    n = max(1, min(400, -int(-(b - start) // step)))
    return start, step, n


def _nice_axis(top: int) -> tuple[int, int]:
    """(axis maximum, tick step) for counts up to `top`: steps of 1, 2 or 5 times a power of ten."""
    if top <= 4:
        return max(top, 1), 1
    raw, mag = top / 4, 1
    while mag * 10 <= raw:
        mag *= 10
    tick = next(m * mag for m in (1, 2, 5, 10) if m * mag >= raw)
    return -(-top // tick) * tick, tick


def _span_text(a: float, b: float) -> str:
    return f'<span>{_ts(a)}</span><span>{_ts(b)}</span>'


def _timeline(hist: dict, window: tuple[int, int] | None, t: str, params: dict[str, str] | None,
              now: float, total: int = 0) -> tuple[str, str]:
    """(histogram, top-bar range picker). Sycope-like histogram of the matching jobs by alert time, with its range controls: presets,
    shift left/right, zoom out; dragging over the bars (or a click on one) zooms in (_QUEUE_JS)."""
    start, step, counts = int(hist["start"]), int(hist["step"]), list(hist["counts"])
    n = len(counts) or 1
    ymax, tick = _nice_axis(max(counts) if counts else 0)
    end = start + step * n
    fmt = "hm" if end - start <= 86400 else ("dhm" if step < 86400 else "d")
    bars = "".join(
        f'<div class="{"" if c else "z"}" style="height:{(c / ymax * 100) if c else 0:.2f}%" data-e="{start + i * step}" '
        f'data-c="{c}"></div>' for i, c in enumerate(counts))
    grid = "".join(f'<i style="bottom:{v / ymax * 100:.2f}%"><b>{v}</b></i>' for v in range(0, ymax + 1, tick))
    every = -(-n // 8)
    xl = "".join(f'<span style="left:{(i + 0.5) / n * 100:.3f}%">{_ts(start + i * step, fmt)}</span>'
                 for i in range(0, n, every))

    def link(cls: str, label: str, title: str, tt: str | None, on: bool = True) -> str:
        if not on:
            return f'<span class="{cls} off" title="{_e(title)}">{label}</span>'
        return f'<a class="{cls}" href="{_e(_url(params, t=tt, page=None, open=None))}" title="{_e(title)}">{label}</a>'

    if window:
        a, b = window
        d = b - a
        prev = link("tlnav", "&#8249;", "Earlier", f"{a - d}-{b - d}")
        nxt = link("tlnav", "&#8250;", "Later", f"{a + d}-{b + d}" if b + d <= now else f"{int(now) - d}-{int(now)}",
                   on=b < now - 1)
        c = (a + b) // 2
        keys = [k for k, _ in _PRESETS]
        if t in keys:  # a range ending now widens to the next preset and keeps following now
            out_t = keys[keys.index(t) + 1] if keys.index(t) + 1 < len(keys) else None
        elif 2 * d > MAX_WINDOW:
            out_t = None
        else:
            za, zb = c - d, c + d
            if zb > now:
                za, zb = int(now) - 2 * d, int(now)
            out_t = f"{za}-{zb}"
        zoom = link("tlbtn", "&minus;", "Zoom out (twice the range)", out_t)
        shown = _span_text(a, b)
    else:
        prev = '<span class="tlnav off">&#8249;</span>'
        nxt = '<span class="tlnav off">&#8250;</span>'
        zoom = '<span class="tlbtn off">&minus;</span>'
        shown = _span_text(start, end) if counts and any(counts) else '<span>All jobs</span><span>no jobs yet</span>'
    label = dict(_PRESETS).get(t, "Custom range" if window else "All jobs")
    short = t if t in dict(_PRESETS) else ("abs" if window else "all")
    items = "".join(f'<a class="mi{" cur" if k == t else ""}" href="{_e(_url(params, t=k, page=None, open=None))}">'
                    f'<b>{k}</b> {_e(v)}</a>' for k, v in _PRESETS)
    items += (f'<a class="mi{" cur" if not window else ""}" href="{_e(_url(params, t=None, page=None, open=None))}">'
              f'<b>all</b> Every job</a>')
    zoom_mi = (zoom.replace('class="tlbtn"', 'class="mi"').replace('class="tlbtn off"', 'class="mi off"')
               .replace("&minus;", "<b>&minus;</b> Zoom out (wider range)"))
    ca, cb = (window if window else (start, end))
    custom = (f'<form class="tcus" id="tcus" data-a="{int(ca)}" data-b="{int(cb)}">'
              '<label>From<input type="datetime-local" step="1" id="tc-a" required></label>'
              '<label>To<input type="datetime-local" step="1" id="tc-b" required></label>'
              '<button type="submit" class="btn-del" style="background:var(--blue)">Apply</button></form>')
    clear = (f'<a class="tclr" href="{_e(_url(params, t=None, page=None, open=None))}" title="Clear the time range">'
             f'&times;</a>' if window else "")
    picker = (f'<div class="tpk"><details class="dd tlr"><summary title="Time range (alert time): {_e(label)}">'
              f'{_CAL}<span class="tlp">{_e(short)}</span><span class="tld mono">{shown}</span></summary>'
              f'<div class="ddp"><div class="gh">Quick ranges (alert time)</div>{items}{zoom_mi}'
              f'<div class="gh">Custom range</div>{custom}</div></details>{clear}</div>')
    per = f"{step // 86400} d" if step >= 86400 else (f"{step // 3600} h" if step >= 3600 else f"{step // 60} min")
    chart = (f'<div class="tl" data-start="{start}" data-step="{step}" data-n="{n}">'
             f'{prev}<div class="tly"><span class="tlyl">Count</span></div>'
             f'<div class="tlp2"><span class="hits">{_e(total)} Hits</span><div class="tlg">{grid}</div>'
             f'<div class="tlb">{bars}</div><div class="brush"></div></div>'
             f'{nxt}</div><div class="tlx">{xl}</div>'
             f'<div class="mut tlcap">Jobs by alert time, {per} per bar. Drag over the bars to zoom in.</div>')
    return chart, picker


# queue columns: (key, header label, field name shown under it, ?sort= key or None, grid width, on by default,
# help). The sort keys are those of store.JobStore.SORTS. The first grid column (checkbox and caret) is fixed.
QUEUE_COLS = [
    ("alert", "Alert Name", "alertName", "alert", "minmax(220px,2.4fr)", True,
     "The alert's name from Sycope; hover it for the alert id (the status page is <base>/<id>, the file is "
     "<id>?download=1). A star marks a persistent job: its row is kept from bulk delete and pruning, and its PCAP "
     "from retention. Click a row to expand every detail: window, BPF filter, history."),
    ("alert_id", "Alert ID", "alertId", "alert_id", "200px", False,
     "The alert id: the key of the status page <base>/<id> and of the file <id>?download=1."),
    ("severity", "Alert Severity", "alertSeverity", "severity", "128px", True,
     "The alert's severity in Sycope (LOW, MEDIUM, HIGH, CRITICAL). Sorting puts the most severe first when "
     "descending."),
    ("state", "State", "state", "state", "112px", True,
     "queued: waiting for its due time (see Due) or for a free worker.\nrunning: npcapextract is extracting "
     "now.\ndone: the PCAP exists (see PCAP).\nmiss: the window was searched and held no packets (after the "
     "retries, each looking further back). Usually the traffic never reached the recorder, or the rolling buffer "
     "no longer covers it.\nfailed: an error (details in the row and the debug logs).\nThe chips above filter by "
     "state; \"persistent\" is your own flag."),
    ("client", "Client IP", "clientIp", "client_ip", "128px", False, "The alert's client address."),
    ("server", "Server IP", "serverIp", "server_ip", "128px", False, "The alert's server address."),
    ("port", "Server Port", "serverPort", "server_port", "96px", False, "The alert's server port."),
    ("proto", "Protocol", "protocol", "protocol", "88px", False, "The alert's IP protocol."),
    ("attempts", "Attempts", "attempts", "attempts", "104px", True,
     "How many times extraction ran for this job. 0 = not started yet. A miss or error is retried "
     "(SR_JOB_MAX_ATTEMPTS, default 3), each retry after SR_JOB_RETRY_DELAY_SECONDS and with a wider window "
     "backwards."),
    ("alert_time", "Alert Time", "alertTime", "alert_time", "152px", True,
     "When the alert fired for Sycope: the END of the minute bucket the alert counts, not the moment the webhook "
     "arrived. The extraction window is built around it: [T - range - lag, T + margin]."),
    ("due", "Due", "readyAt", "due", "152px", True,
     "The earliest moment extraction may start: the window end + the length of one n2disk file "
     "(SR_CHUNK_SECONDS, 300 s) + a margin. Until the file holding the window end is closed, npcapextract cannot "
     "see that data. So every job waits about 6 minutes after its alert time, and jobs run in Due order, not in "
     "the order their webhooks arrived. Sort by Due ascending to see exactly what runs next."),
    ("updated", "Updated", "updated", "updated", "152px", True,
     "The last change of the job: for a queued job when its webhook arrived, for a done job when the PCAP was "
     "finished. That is why queued and done rows seem out of order if you sort by it."),
    ("profile", "Profile", "profile", "profile", "140px", False,
     "The extraction profile of the alert's definition that built the filter and window, if any."),
    ("persistent", "Persistent", "persistent", "persistent", "96px", False,
     "Yes when the job is flagged persistent: its row survives bulk delete and pruning and its PCAP is never "
     "deleted by the retention sweep."),
    ("pcap", "PCAP", "pcapBytes", "pcap", "104px", True,
     "The extracted file and its size (click to download). Empty until the job is done; \"deleted\" means the "
     "file was removed from disk afterwards."),
    ("detail", "Detail", "detail", None, "minmax(160px,2fr)", True,
     "A short note: why a job waits, a warning (for example the window may have cut the beginning of the "
     "traffic) or the last error."),
]
_SEL_W = "56px"
_KB_W = "40px"  # the row's actions menu (⋮), always the last column
_INFO_COLS = ("due", "detail")  # the only headings whose meaning is not plain from the name (owner's choice)


def _visible(keys: list[str] | None = None) -> list[str]:
    return keys if keys else [c[0] for c in QUEUE_COLS if c[5]]


def _cols_css(visible: list[str]) -> str:
    """CSS hiding the columns that are not selected (the script rewrites it from the stored choice)."""
    hide = [f".jobs .c-{c[0]}" for c in QUEUE_COLS if c[0] not in visible]
    return (",".join(hide) + "{display:none}") if hide else ""


def _grid_cols(visible: list[str]) -> tuple[str, int]:
    """grid-template-columns of the selected columns, and the minimum width they need."""
    widths = [c[4] for c in QUEUE_COLS if c[0] in visible]
    minimum = 56 + sum(int(m.group(1)) if (m := re.search(r"(\d+)px", w)) else 0 for w in widths)
    return " ".join([_SEL_W] + widths + [_KB_W]), minimum + 40


def _sort_head(params: dict | None, sort: str, desc: bool, editable: bool) -> str:
    """The header row: a select-all box, then each column as a sort link over its field name, with its (i)."""
    box = ('<span class="c-sel"><input type="checkbox" id="select-all" title="Select all on this page"></span>'
           if editable else '<span class="c-sel"></span>')
    cells = []
    for key, label, fld, skey, _w, _d, tip in QUEUE_COLS:
        if skey:
            nxt = "asc" if (sort == skey and desc) else "desc"
            arrow = (f' <span class="arr">{"&#9660;" if desc else "&#9650;"}</span>' if sort == skey else "")
            text = (f'<a href="{_e(_url(params, sort=skey, dir=nxt, page=1))}" title="Sort by {_e(label)}">'
                    f'{_e(label)}{arrow}</a>')
        else:
            text = _e(label)
        cells.append(f'<span class="c-{key}"><span class="hl">{text}{_info(tip) if key in _INFO_COLS else ""}</span>'
                     f'<span class="fld">{_e(fld)}</span>'
                     f'<span class="rsz" data-rsz="{key}" title="Drag to resize, double-click to reset"></span></span>')
    return box + "".join(cells) + '<span class="c-kb"></span>'


def _url(params: dict[str, str] | None, **overrides: object) -> str:
    """Build a query string preserving current parameters with overrides applied."""
    merged = dict(params or {})
    for k, v in overrides.items():
        if v is None or v == "" or (k == "page" and str(v) == "1"):
            merged.pop(k, None)
        else:
            merged[k] = str(v)
    if any(k in overrides for k in ("page", "size", "state", "open")) and "msg" not in overrides:
        merged.pop("msg", None)
    if not merged:
        return "?"
    return "?" + urllib.parse.urlencode(merged)


_FIELD_NAMES = {"alertname": "alertName", "alertid": "alertId", "severity": "severity", "state": "state",
                "clientip": "clientIp", "serverip": "serverIp", "serverport": "serverPort", "protocol": "protocol",
                "profile": "profile"}


def _token(key: str, value: object) -> str:
    v = str(value)
    return f'{_FIELD_NAMES[key]}="{v}"' if (" " in v or not v) else f"{_FIELD_NAMES[key]}={v}"


def split_q(q: str) -> tuple[list[tuple[str, str, str]], str]:
    """([(token, field key, value) of each field filter], the free text) of a search."""
    fields, free = [], []
    for tok in search_tokens(q):
        ft = field_token(tok)
        if ft:
            fields.append((tok, ft[0], ft[1]))
        else:
            free.append(f'"{tok}"' if " " in tok else tok)
    return fields, " ".join(free)


def _fv(params: dict[str, str] | None, key: str, value: object, inner: str) -> str:
    """A cell value that adds the filter `field=value` (Sycope: filter by value) when clicked."""
    if value in (None, ""):
        return inner
    q = (params or {}).get("q", "")
    tok = _token(key, value)
    if tok in search_tokens(q):
        return inner
    return (f'<a class="fv" href="{_e(_url(params, q=(q + " " + tok).strip(), page=None, open=None))}" '
            f'title="Filter: {_e(tok)}" onclick="event.stopPropagation()">{inner}</a>')


def raw_data_url(sycope_url: str, j: dict) -> str:
    """Sycope's Raw Data view of this job's flow over its extraction window (owner's format, Sycope 3.3):
    NQL from the alert's addresses and port, re-validated here, and the window as ISO times with the
    offset. "" without SR_SYCOPE_URL or without an address."""
    base = (sycope_url or "").strip().rstrip("/")
    if not re.match(r"^https?://[A-Za-z0-9.:\[\]-]+$", base):
        return ""
    m = meta_of(j)
    terms = []
    for field in ("clientIp", "serverIp"):
        try:
            ip = ipaddress.ip_address(str(m.get(field) or "").strip())
        except ValueError:
            continue
        if getattr(ip, "scope_id", None) is None:  # a scope id may hold any text, quotes too (a row from before the fix)
            terms.append(f'{field} = "{ip}"')
    if not terms:
        return ""
    port = str(m.get("serverPort") or "")
    if port.isdigit() and 0 < int(port) < 65536:
        terms.append(f"serverPort = {int(port)}")
    try:  # from epochs, so each bound gets its own offset (the end's epoch is stored, the start's read back)
        frm = datetime.fromtimestamp(local_epoch(j["window_begin"])).astimezone().isoformat(timespec="seconds")
        to = datetime.fromtimestamp(float(j["window_end_epoch"])).astimezone().isoformat(timespec="seconds")
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return ""
    gq = {"query": {"source": "netflow", "nql": " and ".join(terms), "advanced": False},
          "timerange": {"from": frm, "to": to, "roundTo": "minute"}}
    return (f"{base}/panel/raw-data/list?source=netflow&gq="
            f"{urllib.parse.quote(json.dumps(gq, separators=(',', ':')), safe=':,')}&direction=-1&groupType=all")


def _job_dl(j: dict) -> str:
    return f'{j["alert_key"]}?download=1&job={urllib.parse.quote(str(j["id"]))}'


_CHILD = re.compile(r"^re-extracted as (\S+\.pcap) ")


def _children(events: list[dict]) -> list[tuple[str, float | None]]:
    """(file, when) of the jobs an operator re-extracted from this one, from its `reextract` events."""
    return [(m.group(1), ev.get("ts")) for ev in events if (m := _CHILD.match(str(ev.get("detail") or "")))]


def _origin(j: dict, rx: dict | None, events: list[dict]) -> str:
    """Where this job came from (only that: what was made from it is under Re-extractions), with a link to all
    jobs of the alert in the queue when there is more than one."""
    every = _url({}, q=f"alertId={j['alert_id']}")
    if rx:
        text = (f're-extract of <code>{_e(j.get("parent_id"))}</code> by an operator ({_e(rx.get("filter"))} '
                f'filter, {int(rx.get("before", 0)):+d} s / {int(rx.get("after", 0)):+d} s)')
    else:
        text = "Sycope webhook"
    if rx or _children(events):
        text += f' &middot; <a href="{_e(every)}">all jobs of this alert</a>'
    return text


def _reextractions(events: list[dict]) -> str:
    """The files an operator made from this job (newest last); "" when none, so the field is left out."""
    kids = _children(events)
    return "<br>".join(f"<code>{_e(k)}</code> ({_ts(ts)})" for k, ts in kids) if kids else ""


def _pcap_info_text(j: dict) -> str:
    """"1234 packets, 10:00:01 to 10:04:59" (HTML: local times) from the worker's summary of the file,
    "" without one."""
    try:
        info = json.loads(j.get("pcap_info") or "{}")
    except ValueError:
        return ""
    if not isinstance(info, dict) or "packets" not in info:
        return ""
    if not info.get("packets"):
        return "0 packets"
    return f'{info["packets"]} packets, {_ts(info.get("first"))} to {_ts(info.get("last"))}'


def _dl(j: dict, size: int | None, big: bool = False) -> str:
    """Download link for a finished job (the alert link returns the PCAP as an attachment)."""
    if j["state"] != DONE:
        return _cell("")
    if size is None:
        return '<span class="mut">deleted</span>'
    label = f"Download PCAP ({_e(_size(size))})" if big else f"&#8595; {_e(_size(size))}"
    # this job's own file: an alert re-extracted by an operator has several
    return (f'<a class="{"dlbig" if big else "dl"}" href="{_e(_job_dl(j))}" '
            f'title="Download {_e(j["id"])}">{label}</a>')


def _row(j: dict, events: list[dict], opened: bool, size: int | None = None,
         params: dict[str, str] | None = None, editable: bool = False, slot: dict | None = None,
         sycope_url: str = "") -> str:
    """One job: a grid row that expands (<details>) into everything about it; the page scripts
    keep it open across refreshes and drive its menu and Re-extract from its data-job."""
    key = _e(j["alert_key"])
    m = meta_of(j)
    name = m.get("name")
    persistent = bool(j.get("persistent", 0))
    is_running = j.get("state") == RUNNING
    star_title = "Unmark persistent" if persistent else "Mark as persistent"
    star_char = "&#9733;" if persistent else "&#9734;"
    if not editable:
        chk = ""
        star_form = f'<span class="star-btn{" on" if persistent else ""}">{star_char}</span>' if persistent else ""
    else:
        # Every row is tickable: a running job can be cancelled (delete still skips it server-side).
        title = ' title="Running: can be cancelled, not deleted"' if is_running else ""
        chk = (f'<input type="checkbox" name="job_id" value="{_e(j["id"])}" class="row-chk"{title} '
               f'onclick="event.stopPropagation()">')
        # A <form> may not nest inside the bulk form (the parser drops the inner tag): the button
        # belongs to the one star form outside it through the `form` attribute.
        star_form = (f'<button type="submit" form="star-form" name="job_id" value="{_e(j["id"])}" '
                     f'class="star-btn{" on" if persistent else ""}" title="{star_title}" '
                     f'onclick="event.stopPropagation()">{star_char}</button>')
    detail_cell = _cell("cancelling... " + str(j["detail"])
                        if j.get("cancel_requested") and j["state"] == RUNNING else j["detail"])
    cells = {
        "alert": (f'{star_form}<span class="ell nm" data-full="{_e(name or "")}\n{key}" data-always="1">'
                  f'{_cell(name)}</span>'
                  + (' <span class="rxb" title="Re-extracted by an operator">re-extract</span>'
                     if j.get("origin") == "operator" else "")),
        "alert_id": f'<span class="ell">{key}</span>',
        "severity": _fv(params, "severity", m.get("severity"), _sev(m.get("severity"))) if m.get("severity")
        else _cell(""),
        "state": _fv(params, "state", j["state"], _badge(j["state"])),
        "client": _fv(params, "clientip", m.get("clientIp"), _cell(m.get("clientIp"))),
        "server": _fv(params, "serverip", m.get("serverIp"), _cell(m.get("serverIp"))),
        "port": _fv(params, "serverport", m.get("serverPort"), _cell(m.get("serverPort"))),
        "proto": _fv(params, "protocol", m.get("protocol"), _cell(m.get("protocol"))),
        "attempts": _cell(j["attempts"]),
        "alert_time": _ts(m.get("alertTime")),
        "due": _ts(j["ready_at"]),
        "updated": _ts(j["updated"]),
        "profile": _fv(params, "profile", m.get("profile"), _cell(m.get("profile"))),
        "persistent": '<span class="badge b-persistent">&#9733; yes</span>' if persistent else '<span class="mut">no</span>',
        "pcap": _dl(j, size),
        "detail": f'<span class="ell">{detail_cell}</span>',
    }
    for k in ("client", "server", "profile"):
        cells[k] = f'<span class="ell">{cells[k]}</span>'
    body_cells = "".join(f'<span class="c-{k}">{cells[k]}</span>' for k, *_ in QUEUE_COLS)
    rx = m.get("reextract") if isinstance(m.get("reextract"), dict) else None
    data = {"id": j["id"], "key": j["alert_key"], "name": name or "", "state": j["state"], "bpf": j["bpf"],
            "wb": j["window_begin"], "we": j["window_end"], "c": m.get("clientIp") or "",
            "s": m.get("serverIp") or "", "p": m.get("serverPort") or "", "pr": m.get("protocol") or "",
            "dl": _job_dl(j) if j["state"] == DONE and size is not None else "", "rd": raw_data_url(sycope_url, j)}
    kebab = ('<span class="c-kb"><button type="button" class="kb" aria-label="Actions" title="Actions" '
             'onclick="event.preventDefault()">&#8942;</button></span>')
    summary = (f'<summary data-job="{_e(json.dumps(data))}"><span class="c-sel">{chk}<span class="caret"></span>'
               f'</span>{body_cells}{kebab}</summary>')
    hist = "".join(
        f"<tr><td>{_ts(ev['ts'])}</td><td>{_badge(ev['state'])}</td>"
        f"<td>{_cell(ev['attempt'])}</td><td>{_cell(_size(ev['bytes']))}</td>"
        f"<td>{_cell(ev['detail'])}</td></tr>" for ev in events)
    done_link = (f' &middot; <a href="{_e(_job_dl(j))}">Download PCAP</a>'
                 if j["state"] == DONE else "")
    worker_kv = (_kv("Worker", _e(f'{slot["slot"]}, step {slot.get("step") or "-"} for '
                                  f'{int(time.time() - (slot.get("step_started") or time.time()))} s'))
                 if slot else "")
    job_kv = "".join([
        _kv("File", f'<code>{_e(j["id"])}</code>'),
        _kv("BPF filter", f'<code>{_e(j["bpf"])}</code>'),
        _kv("Extraction window (server time)", f'{_e(j["window_begin"])} to {_e(j["window_end"])}'),
        _kv("Due after", _ts(j["ready_at"])),
        _kv("Created", _ts(j["created"])),
        _kv("Persistent", '<span class="badge b-persistent">&#9733; yes</span>' if persistent else "no"),
        _kv("PCAP content", (_pcap_info_text(j) or _cell("")) if j["state"] == DONE else _cell("")),
        _kv("Origin", _origin(j, rx, events)),
        _kv("Re-extractions", _reextractions(events)) if _children(events) else "",
        worker_kv,
        _kv("Links", f'<a href="{key}">Status page</a>{done_link} &middot; '
                     f'<a href="{key}?format=json">JSON</a>'
                     + (f' &middot; <a href="{_e(data["rd"])}" target="_blank" rel="noopener">Open in Raw Data</a>'
                        if data["rd"] else "")),
    ])
    # One row of equal buttons: the download first, then what the operator may do with the job.
    actions = []
    if j["state"] == DONE:
        actions.append(f'<a class="bact" href="{_e(_job_dl(j))}" title="Download {_e(j["id"])}">'
                       f'Download PCAP ({_e(_size(size))})</a>' if size is not None
                       else '<span class="mut">PCAP deleted from disk</span>')
    if editable and j["state"] in (QUEUED, RUNNING) and not j.get("cancel_requested"):
        actions.append(f'<button type="submit" form="act-form" formaction="queue-cancel" name="job_id" '
                       f'value="{_e(j["id"])}" class="bact red" onclick="return confirm(\'Cancel this job?\')">'
                       f'Cancel</button>')
    if editable and j["state"] in (MISS, FAILED, CANCELLED):
        actions.append(f'<button type="submit" form="act-form" formaction="queue-retry" name="job_id" '
                       f'value="{_e(j["id"])}" class="bact">Retry</button>')
    if editable:
        actions.append('<button type="button" class="bact rx-open" '
                       'title="Extract this alert again with another window or filter (a new file; this one stays)">'
                       'Re-extract&hellip;</button>')
    act_html = f'<div class="acts">{"".join(actions)}</div>' if actions else ""
    body = (f'<div class="more">{act_html}<h3>Alert</h3>{_alert_kv(j)}<h3>PCAP job</h3>'
            f'<div class="kv">{job_kv}</div><h3>History</h3>'
            '<div class="grid"><table><tr><th>Time</th><th>Event</th><th>Attempt</th>'
            f"<th>Size</th><th>Detail</th></tr>{hist}</table></div></div>")
    return f'<details class="job" data-id="{_e(j["id"])}"{" open" if opened else ""}>{summary}{body}</details>'


_CHEV = ('<svg class="chev" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">'
         '<path d="M1.5 3.5 5 7l3.5-3.5" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>')
_LUPA = ('<svg class="lupa" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="6.5" '
         'cy="6.5" r="4.6" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M10 10l4.2 4.2" '
         'stroke="currentColor" stroke-width="1.4" fill="none"/></svg>')
_GEAR = _gear(20)

_ACTIONS = (  # label, formaction, submitter value, verb (the confirm text), css
    ("Cancel jobs", "queue-cancel", None, "Cancel", ""),
    ("Retry jobs", "queue-retry", None, "Retry", ""),
    ("Mark persistent", "queue-persistent", "1", "Mark persistent", ""),
    ("Unmark persistent", "queue-persistent", "0", "Unmark persistent", ""),
    ("Delete jobs", "delete", None, "Delete", " del"),
)


def _toolbar(params: dict[str, str] | None, state: str | None, q: str, sort: str, desc: bool, size: int,
             editable: bool, expand_open: bool, visible: list[str]) -> str:
    """Above the table: Action (bulk), then at the right the column selector, saved views, Search, settings."""
    action = ""
    if editable:
        items = "".join(
            f'<button type="submit" form="bulk-form" formaction="{a}"{f" name=value value={v}" if v else ""} '
            f'class="mi{css}" data-verb="{_e(verb)}" disabled>{_e(label)}</button>'
            for label, a, v, verb, css in _ACTIONS)
        items += ('<button type="button" form="bulk-form" class="mi" id="act-zip" disabled '
                  'title="The PCAPs of the ticked finished jobs as one zip (at most 500 files, 4 GiB)">'
                  'Download PCAPs (zip)</button>')
        items += ('<button type="button" form="bulk-form" class="mi" id="act-rx" disabled '
                  'title="A new extraction of every ticked job with a wider window (same filters)">'
                  'Re-extract with wider window&hellip;</button>')
        action = (f'<details class="dd act"><summary id="actsum"><span class="al">Action</span>{_CHEV}</summary>'
                  f'<div class="ddp">{items}</div></details>')
    cols = "".join(
        f'<label class="mi"><input type="checkbox" data-col="{c[0]}"'
        f'{" checked" if c[0] in visible else ""}{" disabled checked" if c[0] == "alert" else ""}> {_e(c[1])}</label>'
        for c in QUEUE_COLS)
    columns = (f'<details class="dd cols"><summary><span id="colcount">{len(visible)} columns</span> {_CHEV}'
               f'</summary><div class="ddp">{cols}</div></details>')
    views = (f'<details class="dd views"><summary><span id="viewname">Views</span> {_CHEV}</summary>'
             '<div class="ddp" id="viewlist"><button type="button" class="mi" id="saveview">'
             'Save current view...</button></div></details>')
    fields, free = split_q(q)
    hidden = "".join(f'<input type="hidden" name="{n}" value="{_e(v)}">' for n, v in
                     (("state", state or ""), ("sort", sort), ("dir", "desc" if desc else "asc"), ("size", size),
                      ("t", (params or {}).get("t", "")), ("qf", " ".join(tok for tok, _k, _v in fields))) if v)
    chips = "".join(
        f'<span class="fchip"><button type="button" class="fced" data-i="{i}" title="Edit: {_e(tok)}">'
        f'<span class="fk">{_e(FIELDS[k][0])}</span><span class="fvv">{_e(v)}</span></button>'
        f'<a href="{_e(_url(params, q=" ".join(t2 for t2, *_ in fields if t2 != tok) + (" " + free if free else ""), page=1))}" '
        f'title="Remove this filter">&times;</a></span>' for i, (tok, k, v) in enumerate(fields))
    fdata = json.dumps({"fields": [{"tok": tok, "k": k, "v": v} for tok, k, v in fields], "free": free,
                        "names": {k: [_FIELD_NAMES[k], FIELDS[k][0]] for k in FIELDS}})
    chips += ('<button type="button" class="fadd" id="fadd" title="Add a filter (field = value, wildcard *, network '
              'a.b.c.d/n, several values a,b)">+</button>')
    opts = "".join(f'<option value="{k}">{_e(lbl)}</option>' for k, (lbl, _x) in FIELDS.items())
    pop = (f'<div id="fpop" class="fpop" hidden><select id="fp-f" aria-label="Field">{opts}</select>'
           '<input type="text" id="fp-v" maxlength="200" autocomplete="off" '
           'placeholder="value, 10.88.* or 10.0.0.0/8; a,b for either">'
           '<div class="fp-n" id="fp-n"></div><div class="fp-list" id="fp-list"></div>'
           '<div class="fp-foot"><button type="button" class="btn-sec" id="fp-clear">Clear filter</button>'
           '<button type="button" class="btn-pri" id="fp-apply">Apply</button></div></div>')
    clear = (f'<a class="clr" href="{_e(_url(params, q=" ".join(t2 for t2, *_ in fields) or None, page=1))}" '
             f'title="Clear the search text">&times;</a>' if free else "")
    search = (f'<div class="fchips" id="fchips" data-f="{_e(fdata)}">{chips}</div>{pop}'
              f'<form class="srch" method="get" action="queue">{hidden}{_LUPA}'
              f'<input type="search" name="q" value="{_e(free)}" placeholder="Search" maxlength="300" '
              f'aria-label="Search" title="Free text: alert, flow, state, time, profile, window or size (1.5MB). '
              f'Words are ANDed; use quotes for a phrase. Field filters: clientIp=10.88.* (wildcard), '
              f'serverIp=10.0.0.0/8 (network), serverPort=443, protocol=tcp, state=done, severity=high, '
              f'profile=..., alertName=..., alertId=...; click a value in the table to add one.">'
              f'<button type="submit" class="vh">Search</button>'
              f'{clear}</form>')
    sizes = "".join(
        f'<span class="mi cur">{s}</span>' if s == size else f'<a class="mi" href="{_e(_url(params, size=s, page=1))}">{s}</a>'
        for s in (50, 100, 200, 500))
    if expand_open:
        rows_ctl = (f'<a class="mi" href="{_e(_url(params, open="all"))}" id="btn-exp-all">expand all</a>'
                    f'<a class="mi" href="{_e(_url(params, open=None))}" id="btn-col-all">collapse all</a>')
    else:
        rows_ctl = (f'<a class="mi" href="{_e(_url(params, open="all"))}" id="btn-exp-all">expand all</a>'
                    f'<a class="mi" href="{_e(_url(params, open=None))}" id="btn-col-all" style="display:none">'
                    f'collapse all</a>')
    gear = (f'<details class="dd gear right"><summary aria-label="Settings" title="Settings">{_GEAR}</summary>'
            f'<div class="ddp"><div class="gh">Rows per page</div>{sizes}<div class="gh">open rows</div>{rows_ctl}'
            f'</div></details>')
    return f'<div class="tools">{action}<span class="sp"></span>{columns}{views}{search}{gear}</div>'


_QUEUE_JS = r"""
(function(){
var $=function(s){return document.querySelector(s)},$$=function(s){return Array.prototype.slice.call(document.querySelectorAll(s))};
var jobs=$(".jobs"),LS=null;try{LS=window.localStorage}catch(e){}
function get(k,d){try{var v=LS&&LS.getItem(k);return v?JSON.parse(v):d}catch(e){return d}}
function put(k,v){try{LS&&LS.setItem(k,JSON.stringify(v))}catch(e){}}
var defs=JSON.parse(jobs.getAttribute("data-cols")),keys=defs.map(function(d){return d.k}),cur=get("sr.queue.cols",null);
if(!(Array.isArray(cur)&&cur.length&&cur.indexOf("alert")>=0&&cur.every(function(k){return keys.indexOf(k)>=0})))
  cur=defs.filter(function(d){return d.d}).map(function(d){return d.k});
var widths=get("sr.queue.widths",{});if(!widths||typeof widths!=="object")widths={};
function wOf(d){var w=+widths[d.k];return w>=40&&w<=2000?w+"px":d.w}
var order=get("sr.queue.order",null);
function okOrder(o){return Array.isArray(o)&&o.every(function(k){return keys.indexOf(k)>=0})}
if(!okOrder(order))order=keys.slice();
keys.forEach(function(k){if(order.indexOf(k)<0)order.push(k)});
function applyCols(list){
  cur=list;var on=order.map(function(k){return defs[keys.indexOf(k)]}).filter(function(d){return list.indexOf(d.k)>=0});
  var css=defs.filter(function(d){return list.indexOf(d.k)<0}).map(function(d){return".jobs .c-"+d.k}).join(",");
  $("#colcss").textContent=(css?css+"{display:none}":"")+order.map(function(k,i){return".jobs .c-"+k+"{order:"+(i+1)+"}"}).join("")+".jobs .c-kb{order:999}";
  var min=96;on.forEach(function(d){var m=/(\d+)px/.exec(wOf(d));if(m)min+=+m[1]});
  jobs.style.setProperty("--cols",["56px"].concat(on.map(wOf)).concat(["40px"]).join(" "));
  jobs.style.setProperty("--minw",min+"px");
  $$("[data-col]").forEach(function(c){c.checked=list.indexOf(c.getAttribute("data-col"))>=0});
  $("#colcount").textContent=list.length+" columns";
}
$$("[data-col]").forEach(function(c){c.onchange=function(){
  var l=defs.filter(function(d){return d.k==="alert"||$("[data-col="+d.k+"]").checked}).map(function(d){return d.k});
  put("sr.queue.cols",l);applyCols(l);paintViews()}});
var FIELDS=["q","state","sort","dir","size","t"],views=get("sr.queue.views",{});
function here(){var p=new URLSearchParams(location.search),o={};FIELDS.forEach(function(k){o[k]=p.get(k)||""});return o}
function url(v){var p=new URLSearchParams();FIELDS.forEach(function(k){if(v[k])p.set(k,v[k])});var s=p.toString();return s?"?"+s:"?"}
function same(v){var h=here();return FIELDS.every(function(k){return(v[k]||"")===h[k]})&&JSON.stringify(v.cols)===JSON.stringify(cur)}
function paintViews(){
  var box=$("#viewlist"),name="Views";$$("#viewlist .vrow").forEach(function(n){n.remove()});
  Object.keys(views).forEach(function(n){
    var row=document.createElement("div");row.className="mi vrow";
    var a=document.createElement("a");a.href="#";a.textContent=n;a.onclick=function(e){e.preventDefault();
      put("sr.queue.cols",views[n].cols);if(okOrder(views[n].order))put("sr.queue.order",views[n].order);
      if(views[n].widths)put("sr.queue.widths",views[n].widths);location.href=url(views[n])};
    var x=document.createElement("button");x.type="button";x.className="vx";x.textContent="×";x.title="Delete this view";
    x.onclick=function(e){e.stopPropagation();delete views[n];put("sr.queue.views",views);paintViews()};
    row.appendChild(a);row.appendChild(x);box.insertBefore(row,$("#saveview"));
    if(same(views[n]))name=n});
  $("#viewname").textContent=name;
}
$("#saveview").onclick=function(){
  var n=(prompt("Name of the view (columns and their order and widths, search, state, time range, sorting "
    +"and rows per page)")||"").trim().slice(0,40);
  if(!n)return;var h=here();h.cols=cur;h.order=order;h.widths=widths;views[n]=h;put("sr.queue.views",views);paintViews()};
applyCols(cur);paintViews();
// Column order: drag a header cell onto another one (kept per browser, like the widths).
var dragK=null;
$$(".jhead>span[class^=c-]:not(.c-sel)").forEach(function(c){
  var k=c.className.split(" ")[0].slice(2);if(keys.indexOf(k)<0)return;
  c.draggable=true;$$(".jhead .c-"+k+" a").forEach(function(a){a.draggable=false});
  function clr(){$$(".jhead>span").forEach(function(x){x.classList.remove("dropl","dropr")})}
  c.ondragstart=function(e){dragK=k;c.classList.add("drag");try{e.dataTransfer.setData("text/plain",k);e.dataTransfer.effectAllowed="move"}catch(x){}};
  c.ondragend=function(){dragK=null;c.classList.remove("drag");clr()};
  c.ondragover=function(e){if(!dragK||dragK===k)return;e.preventDefault();var r=c.getBoundingClientRect();clr();
    c.classList.add(e.clientX<r.left+r.width/2?"dropl":"dropr")};
  c.ondragleave=function(){c.classList.remove("dropl","dropr")};
  c.ondrop=function(e){if(!dragK||dragK===k)return;e.preventDefault();var r=c.getBoundingClientRect(),
    after=e.clientX>=r.left+r.width/2,o=order.filter(function(x){return x!==dragK}),i=o.indexOf(k)+(after?1:0);
    o.splice(i,0,dragK);order=o;put("sr.queue.order",order);clr();applyCols(cur)};
});
// Custom time range (top bar): local date-time fields, sent as ?t=<from>-<to> in epoch seconds.
var tc=$("#tcus");
if(tc){
  var pad=function(x){return(x<10?"0":"")+x},loc=function(e){var d=new Date(e*1000);return d.getFullYear()+"-"+pad(d.getMonth()+1)
    +"-"+pad(d.getDate())+"T"+pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds())};
  $("#tc-a").value=loc(+tc.dataset.a);$("#tc-b").value=loc(+tc.dataset.b);
  tc.onsubmit=function(e){e.preventDefault();var a=new Date($("#tc-a").value).getTime()/1000,b=new Date($("#tc-b").value).getTime()/1000;
    if(!(a<b)){alert("From must be before To.");return}var p=new URLSearchParams(location.search);
    p.set("t",Math.floor(a)+"-"+Math.ceil(b));p.delete("page");p.delete("open");p.delete("msg");location.search=p.toString()};
}
// Timeline: local-time bar titles; drag over the bars (or click one) to zoom into that range.
var tl=$(".tl");
if(tl){
  var st=+tl.dataset.start,sp=+tl.dataset.step,nb=+tl.dataset.n,plot=$(".tlp2"),br=$(".brush");
  function p2(x){return(x<10?"0":"")+x}
  function fmt(e){var d=new Date(e*1000);return d.getFullYear()+"-"+p2(d.getMonth()+1)+"-"+p2(d.getDate())+" "+p2(d.getHours())+":"+p2(d.getMinutes())}
  $$(".tlb div").forEach(function(b){var e=+b.dataset.e;b.title=fmt(e)+" - "+fmt(e+sp)+": "+b.dataset.c+" job(s)"});
  function at(x){var r=plot.getBoundingClientRect();return Math.max(0,Math.min(1,(x-r.left)/r.width))}
  function go(a,b){var p=new URLSearchParams(location.search);p.set("t",Math.floor(a)+"-"+Math.ceil(b));p.delete("page");p.delete("open");p.delete("msg");location.search=p.toString()}
  plot.onmousedown=function(e){
    if(e.button!==0)return;e.preventDefault();var f0=at(e.clientX),f1=f0;
    function mv(ev){f1=at(ev.clientX);var l=Math.min(f0,f1),w=Math.abs(f1-f0);br.style.display="block";br.style.left=l*100+"%";br.style.width=w*100+"%"}
    function up(ev){document.removeEventListener("mousemove",mv);document.removeEventListener("mouseup",up);br.style.display="none";
      var r=plot.getBoundingClientRect(),span=nb*sp;
      if(Math.abs(ev.clientX-(r.left+f0*r.width))<4){var i=Math.min(nb-1,Math.floor(f0*nb));go(st+i*sp,st+(i+1)*sp);return}
      var a=st+Math.min(f0,f1)*span,b=st+Math.max(f0,f1)*span;if(b-a>=60)go(a,b)}
    document.addEventListener("mousemove",mv);document.addEventListener("mouseup",up)};
}
// Column widths: drag the right edge of a header cell (kept per browser), double-click it to reset.
$$(".rsz").forEach(function(h){
  var k=h.getAttribute("data-rsz");
  h.onclick=function(e){e.preventDefault();e.stopPropagation()};
  h.ondblclick=function(e){e.preventDefault();e.stopPropagation();delete widths[k];put("sr.queue.widths",widths);applyCols(cur)};
  h.onmousedown=function(e){
    if(e.button!==0)return;e.preventDefault();e.stopPropagation();
    var x0=e.clientX,w0=h.parentNode.getBoundingClientRect().width;h.classList.add("on");document.body.classList.add("resizing");
    function mv(ev){widths[k]=Math.round(Math.max(40,Math.min(2000,w0+ev.clientX-x0)));applyCols(cur)}
    function up(){document.removeEventListener("mousemove",mv);document.removeEventListener("mouseup",up);
      h.classList.remove("on");document.body.classList.remove("resizing");put("sr.queue.widths",widths)}
    document.addEventListener("mousemove",mv);document.addEventListener("mouseup",up)};
});
var f=$("#bulk-form");
if(f&&$("#selbar")){  // the selection bar exists only with SR_QUEUE_EDIT
  var sa=$("#select-all"),sm=$("#chk-all-matching"),rc=$$(".row-chk"),bar=$("#selbar"),sc=$("#sel-count"),ci=$("#confirm-input"),total=__TOTAL__;
  var up=function(){var n=0;rc.forEach(function(c){if(c.checked)n++});var all=sm&&sm.checked;
    sc.textContent=all?total+" selected (all matching)":n+" selected on this page";
    bar.hidden=!(n||all);$$(".mi[form=bulk-form]").forEach(function(b){b.disabled=!(n||all)});
    $("#actsum").classList.toggle("on",!!(n||all))};
  if(sa)sa.onchange=function(){rc.forEach(function(c){c.checked=sa.checked});if(sm&&!sa.checked)sm.checked=false;up()};
  if(sm)sm.onchange=function(){if(sm.checked){if(sa)sa.checked=true;rc.forEach(function(c){c.checked=true})}up()};
  rc.forEach(function(c){c.onchange=function(){if(!c.checked&&sm)sm.checked=false;up()}});
  f.onsubmit=function(e){
    var verb=(e.submitter&&e.submitter.getAttribute("data-verb"))||"Delete",isAll=sm&&sm.checked,n=0;
    rc.forEach(function(c){if(c.checked)n++});var cnt=isAll?total:n;
    if(cnt===0){alert("No jobs selected.");e.preventDefault();return false}
    var q=verb==="Delete"?"Delete "+cnt+" job(s) from the queue? (PCAP files on disk will NEVER be deleted)":verb+" "+cnt+" job(s)?";
    if(confirm(q)){if(verb==="Delete")ci.value="1";return true}
    e.preventDefault();return false};
  up();
}
var ea=$("#btn-exp-all"),ca=$("#btn-col-all");
if(ea)ea.onclick=function(){$$("details.job").forEach(function(d){d.open=true});if(ca)ca.style.display="";return false};
if(ca)ca.onclick=function(){$$("details.job").forEach(function(d){d.open=false});return false};
})();
"""


def queue_page(jobs: list[dict], counts: dict[str, int], state: str | None = None,
               limit: int | None = None,
               events: dict[str, list[dict]] | None = None,
               open_key: str | None = None, sizes: dict[str, int | None] | None = None,
               base_href: str | None = None, params: dict[str, str] | None = None,
               page: int = 1, size: int = 100, total: int = 0, pages: int = 1,
               msg: str | None = None, editable: bool = False, bundle: bool = False,
               sort: str = "alert_time", desc: bool = True, q: str = "",
               worker: dict | None = None, slots: dict[str, dict] | None = None,
               t: str = "", window: tuple[int, int] | None = None, hist: dict | None = None,
               sycope_url: str = "") -> str:
    """The main page: history of all PCAP jobs, each row expandable into its details."""
    now = time.time()
    if hist is None:  # without the store's buckets: the listed jobs over their own span
        times = [float(meta_of(j).get("alertTime") or j.get("created") or now) for j in jobs]
        start, step, n = timeline_span(window, (min(times), max(times)) if times else None, now)
        counts_t = [0] * n
        for x in times:
            if 0 <= int((x - start) // step) < n:
                counts_t[int((x - start) // step)] += 1
        hist = {"start": start, "step": step, "counts": counts_t}
    if limit is not None and (size == 100 or size is None):
        size = limit
    if total == 0 and jobs:
        total = len(jobs)
    events = events or {}
    chips = [f'<a class="chip{" on" if not state or state == "all" else ""}" href="{_e(_url(params, state=None, page=1))}">all</a>']
    chips += [f'<a class="chip{" on" if state == s else ""}" href="{_e(_url(params, state=s, page=1))}">{_e(s)} '
              f"({n})</a>" for s, n in counts.items()]
    head = _sort_head(params, sort, desc, editable)
    rows = "".join(
        _row(j, events.get(j["id"], []), open_key in ("all", j["alert_key"]),
             (sizes or {}).get(j["id"]), params, editable, (slots or {}).get(j["id"]), sycope_url) for j in jobs)
    if not rows:
        rows = f'<div class="empty">{"No job matches this search." if q or state else "No jobs yet."}</div>'

    page_links = []
    if pages > 1:
        if page > 1:
            page_links.append(f'<a href="{_e(_url(params, page=page - 1))}">&laquo; Prev</a>')
        else:
            page_links.append('<span class="dim">&laquo; Prev</span>')

        start_p = max(1, page - 3)
        end_p = min(pages, page + 3)
        if start_p > 1:
            page_links.append(f'<a href="{_e(_url(params, page=1))}">1</a>')
            if start_p > 2:
                page_links.append('<span class="dim">&hellip;</span>')
        for p in range(start_p, end_p + 1):
            if p == page:
                page_links.append(f'<a class="on" href="{_e(_url(params, page=p))}">{p}</a>')
            else:
                page_links.append(f'<a href="{_e(_url(params, page=p))}">{p}</a>')
        if end_p < pages:
            if end_p < pages - 1:
                page_links.append('<span class="dim">&hellip;</span>')
            page_links.append(f'<a href="{_e(_url(params, page=pages))}">{pages}</a>')

        if page < pages:
            page_links.append(f'<a href="{_e(_url(params, page=page + 1))}">Next &raquo;</a>')
        else:
            page_links.append('<span class="dim">Next &raquo;</span>')
    pages_html = f'<div class="pages">{"".join(page_links)}</div>' if pages > 1 else ""
    pbar_html = (f'<div class="pbar">{pages_html}<span class="recs" title="Page {page} of {pages}">'
                 f'{len(jobs)} of {total} records</span></div>')

    chart, picker = _timeline(hist, window, t, params, now, total)
    banner = _toast(msg)
    if worker and worker.get("paused"):
        banner += ('<div class="warnbox">&#9888; Worker paused by an operator: queued jobs do not start. '
                   'Resume it on the System page.</div>')
    elif worker and not worker.get("alive"):
        banner += (f'<div class="warnbox">&#9888; The worker is not running (state {_e(worker.get("state"))}, '
                   f'heartbeat {_e(worker.get("heartbeat_age"))} s ago): jobs are queued but not extracted.</div>')


    visible = _visible()
    grid, minw = _grid_cols(visible)
    cols_json = json.dumps([{"k": c[0], "w": c[4], "d": c[5]} for c in QUEUE_COLS])
    sel_bar = '' if not editable else (
        '<div class="selbar" id="selbar"><span class="sel-count" id="sel-count">0 selected</span>'
        '<label class="sel-opt"><input type="checkbox" name="select_all_matching" value="1" id="chk-all-matching" '
        f'form="bulk-form"> Select all {_e(total)} jobs matching the current filter</label></div>')

    rx_dialog = _RX_DIALOG if editable else ""
    star_form_out = (f'<form id="star-form" method="post" action="persistent">'
                     f'<input type="hidden" name="return_to" value="{_e(_url(params))}"></form>'
                     if editable else "")
    act_form = (f'<form id="act-form" method="post" action="queue-cancel">'
                f'{_keep_fields(state, q, sort, desc, t, window)}'
                f'<input type="hidden" name="size" value="{_e(size)}">'
                f'<input type="hidden" name="page" value="{_e(page)}"></form>' if editable else "")
    body = (
        f'{banner}'
        f'<div class="card">'
        f'<div class="chiprow"><div class="chips">{"".join(chips)}</div>'
        f'{chart}</div></div>'
        f'<div class="card">'
        f'{star_form_out}'
        f'{act_form}'
        f'{_toolbar(params, state, q, sort, desc, size, editable, open_key == "all", visible)}'
        f'{sel_bar}'
        f'<form method="post" action="delete" id="bulk-form">'
        f'{_keep_fields(state, q, sort, desc, t, window)}'
        f'<input type="hidden" name="size" value="{_e(size)}">'
        f'<input type="hidden" name="page" value="{_e(page)}">'
        f'<input type="hidden" name="confirm" value="0" id="confirm-input">'
        f'<div class="jobs" data-cols="{_e(cols_json)}" style="--cols:{grid};--minw:{minw}px">'
        f'<style id="colcss">{_cols_css(visible)}</style>'
        f'<div class="jhead">{head}</div>{rows}</div>'
        f'</form>'
        f'{pbar_html}'
        f'</div>'
        f'<div id="kmenu" class="ddp kmenu" hidden data-edit="{1 if editable else 0}"></div>{rx_dialog}'
        f'<script>{_QUEUE_JS.replace("__TOTAL__", str(int(total)))}{_RX_JS if editable else ""}{_KB_JS}{_FILTER_JS}</script>'
    )
    # Off until the operator turns it on; when on, expanded rows and the re-extract dialog survive it (_RF_JS).
    return _page("Recorder queue", body, refresh=30, refresh_on=False,
                 sub="extraction queue", base_href=base_href, params=params, bundle=bundle, active="queue",
                 topctl=picker)


# The Re-extract dialog: filled from the row's data-job by _RX_JS; the server builds and checks everything.
_RX_DIALOG = (
    '<dialog id="rxd" class="modal"><form id="rxf" method="dialog">'
    '<div class="mh"><h3 class="ct" id="rx-title">Re-extract</h3><button type="button" class="tx" id="rx-x" '
    'aria-label="Close">&times;</button></div>'
    '<div class="mb"><p class="mut" id="rx-sub"></p>'
    '<h4>Window</h4><div class="mut" id="rx-win"></div>'
    '<div class="rxrow"><label>Start earlier by (s)<input type="number" name="before" id="rx-b" value="0" min="-3600" '
    'max="3600" step="1"></label><label>End later by (s)<input type="number" name="after" id="rx-a" value="0" '
    'min="-3600" max="3600" step="1"></label><span class="rxq"><button type="button" data-w="60">&plusmn;1 min</button>'
    '<button type="button" data-w="300">&plusmn;5 min</button><button type="button" data-w="900">&plusmn;15 min'
    '</button><button type="button" data-w="0">reset</button></span></div>'
    '<div id="rx-fsec"><h4>Filter</h4>'
    '<label class="rxr"><input type="radio" name="filter" value="keep" checked> Keep the filter '
    '<code id="rx-bpf"></code></label>'
    '<label class="rxr"><input type="radio" name="filter" value="custom"> Change it</label>'
    '<div id="rx-custom" hidden><div class="rxrow"><label>Protocol<select name="proto" id="rx-pr">'
    '<option value="">any</option><option>tcp</option><option>udp</option><option>icmp</option></select></label>'
    '<label>Ports (comma separated)<input type="text" id="rx-ports" placeholder="443, 8443" maxlength="200"></label>'
    '<label>Addresses must match<select name="match" id="rx-m"><option value="all">all (and)</option>'
    '<option value="any">any (or)</option></select></label></div>'
    '<div id="rx-hosts"></div><button type="button" class="lnk" id="rx-add">+ Add address or network</button></div>'
    '</div>'
    '<h4>Will run</h4><div class="rxp" id="rx-prev">&hellip;</div></div>'
    '<div class="mf"><button type="button" class="btn-sec" id="rx-cancel">Cancel</button>'
    '<button type="submit" class="btn-pri" id="rx-go">Re-extract</button></div>'
    '</form></dialog>')

_RX_JS = r"""
(function(){
var d=document.getElementById("rxd");if(!d||!d.showModal)return;
var $=function(s){return d.querySelector(s)},ids=[],t=null,lastOk=false;
function hostRow(a,dir){var r=document.createElement("div");r.className="rxh";
  r.innerHTML='<input type="text" placeholder="10.0.0.1 or 10.0.0.0/24" maxlength="64"><select><option value="any">either side</option>'
   +'<option value="src">source</option><option value="dst">destination</option></select><button type="button" class="tx" title="Remove">&times;</button>';
  r.querySelector("input").value=a||"";r.querySelector("select").value=dir||"any";
  r.querySelector("button").onclick=function(){r.remove();prev()};r.oninput=prev;r.onchange=prev;$("#rx-hosts").appendChild(r)}
function body(preview){var o={job_id:ids,before:$("#rx-b").value,after:$("#rx-a").value,
  filter:(d.querySelector("input[name=filter]:checked")||{}).value||"keep"};
  if(o.filter==="custom"){o.proto=$("#rx-pr").value;o.match=$("#rx-m").value;o.addr=[];o.dir=[];
    d.querySelectorAll(".rxh").forEach(function(r){o.addr.push(r.querySelector("input").value);o.dir.push(r.querySelector("select").value)});
    o.port=$("#rx-ports").value.split(/[\s,;]+/).filter(Boolean)}
  if(preview)o.preview="1";return o}
function keep(){var o={};new URLSearchParams(location.search).forEach(function(v,k){if(["state","q","sort","dir","size","page","t"].indexOf(k)>=0)o[k]=v});return o}
function prev(){clearTimeout(t);t=setTimeout(function(){
  fetch("queue-reextract",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},
   body:JSON.stringify(body(true)),credentials:"same-origin"}).then(function(r){return r.json()}).then(function(j){
   var p=$("#rx-prev");p.textContent="";lastOk=!j.error;$("#rx-go").disabled=!lastOk;
   if(j.error){p.className="rxp bad";p.textContent=j.error;return}
   p.className="rxp";var l=[(j.jobs>1?j.jobs+" new jobs, the first: ":"New file: ")+j.file,"Window: "+j.begin+" to "+j.end,"Filter: "+j.bpf];
   l.forEach(function(x){var e=document.createElement("div");e.textContent=x;p.appendChild(e)});
   if(j.warning){var w=document.createElement("div");w.className="warn";w.textContent="⚠ "+j.warning;p.appendChild(w)}
  }).catch(function(){$("#rx-prev").textContent="Preview failed"})},250)}
window.srReextract=function(jobs){
  ids=jobs.map(function(j){return j.id});var one=jobs.length===1?jobs[0]:null;
  $("#rx-title").textContent=one?"Re-extract "+(one.name||one.key):"Re-extract "+jobs.length+" jobs with a wider window";
  $("#rx-sub").textContent=one?"A new job for this alert, next to "+one.id+" (its file stays; both can be downloaded).":
    "Each ticked job gets a new job with the same filter and the window below; the old files stay.";
  $("#rx-win").textContent=one?"Now "+one.wb+" to "+one.we+" (server time)":"";
  $("#rx-b").value=0;$("#rx-a").value=0;$("#rx-fsec").hidden=!one;
  d.querySelector("input[name=filter][value=keep]").checked=true;$("#rx-custom").hidden=true;$("#rx-hosts").innerHTML="";
  if(one){$("#rx-bpf").textContent=one.bpf;$("#rx-pr").value=["tcp","udp","icmp"].indexOf(one.pr)>=0?one.pr:"";
    $("#rx-ports").value=one.p?String(one.p):"";if(one.c)hostRow(one.c,"any");if(one.s)hostRow(one.s,"any");if(!one.c&&!one.s)hostRow("","any")}
  d.showModal();prev()};
d.querySelectorAll("input[name=filter]").forEach(function(r){r.onchange=function(){$("#rx-custom").hidden=r.value!=="custom"||!r.checked;prev()}});
d.querySelectorAll(".rxq button").forEach(function(b){b.onclick=function(){$("#rx-b").value=b.dataset.w;$("#rx-a").value=b.dataset.w;prev()}});
["#rx-b","#rx-a","#rx-pr","#rx-ports","#rx-m"].forEach(function(s){$(s).oninput=prev;$(s).onchange=prev});
$("#rx-add").onclick=function(){hostRow("","any");prev()};
$("#rx-x").onclick=$("#rx-cancel").onclick=function(){d.close()};
$("#rxf").onsubmit=function(e){e.preventDefault();if(!lastOk)return;$("#rx-go").disabled=true;
  fetch("queue-reextract",{method:"POST",headers:{"Content-Type":"application/json","Accept":"text/html"},
   body:JSON.stringify(Object.assign(keep(),body(false))),credentials:"same-origin"}).then(function(r){
   if(r.redirected){location.href=r.url;return}return r.text().then(function(x){alert(x)})}).catch(function(x){alert("Request failed: "+x)})};
document.addEventListener("click",function(e){var b=e.target.closest&&e.target.closest(".rx-open");if(!b)return;
  e.preventDefault();var s=b.closest(".job").querySelector("summary");srReextract([JSON.parse(s.dataset.job)])});
var zb=document.getElementById("act-zip");
if(zb)zb.onclick=function(){var f=document.getElementById("bulk-form"),d={},fd=new FormData(f);
  fd.forEach(function(v,k){if(k in d){if(!Array.isArray(d[k]))d[k]=[d[k]];d[k].push(v)}else d[k]=v});
  if(typeof d.job_id==="string")d.job_id=[d.job_id];zb.disabled=true;var old=zb.textContent;zb.textContent="Preparing zip…";
  fetch("queue-zip",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/zip"},body:JSON.stringify(d),
   credentials:"same-origin"}).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(t)});
   var n=(r.headers.get("content-disposition")||"").match(/filename="([^"]+)"/);return r.blob().then(function(b){
   var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=n?n[1]:"pcaps.zip";document.body.appendChild(a);a.click();
   setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},1000)})}).catch(function(e){alert(e.message)})
   .finally(function(){zb.disabled=false;zb.textContent=old})};
var bulk=document.getElementById("act-rx");
if(bulk)bulk.onclick=function(){var js=[];document.querySelectorAll(".row-chk:checked").forEach(function(c){
  js.push(JSON.parse(c.closest("summary").dataset.job))});if(js.length)srReextract(js)};
})();
"""

# Filter chips like Sycope's: a click edits one (field, value, the most frequent values of the current view),
# "+" adds one. The page then reloads with the new search.
_FILTER_JS = r"""
(function(){
var box=document.getElementById("fchips"),pop=document.getElementById("fpop");if(!box||!pop)return;
var D=JSON.parse(box.dataset.f),cur=-1,$=function(s){return pop.querySelector(s)},seq=0;
function tok(k,v){var n=D.names[k][0];return n+"="+(/\s/.test(v)?'"'+v.replace(/"/g,"")+'"':v)}
function others(){return D.fields.filter(function(f,i){return i!==cur}).map(function(f){return f.tok})}
function go(extra){var parts=others();if(extra)parts.push(extra);if(D.free)parts.push(D.free);
  var p=new URLSearchParams(location.search);var q=parts.join(" ").trim();if(q)p.set("q",q);else p.delete("q");
  ["page","open","msg","qf"].forEach(function(k){p.delete(k)});location.search=p.toString()}
function vals(){return $("#fp-v").value.split(",").map(function(x){return x.trim()}).filter(Boolean)}
function load(){var k=$("#fp-f").value,n=++seq,p=new URLSearchParams(location.search),q=others().concat(D.free?[D.free]:[]).join(" ");
  var u=new URLSearchParams({field:k,q:q});["state","t"].forEach(function(x){if(p.get(x))u.set(x,p.get(x))});
  $("#fp-list").innerHTML="";$("#fp-n").textContent="Loading…";
  fetch("queue-values?"+u.toString(),{credentials:"same-origin",headers:{"Accept":"application/json"}}).then(function(r){return r.json()})
  .then(function(j){if(n!==seq)return;$("#fp-n").textContent="Based on "+(j.total||0).toLocaleString()+" records";
    var on=vals();(j.values||[]).forEach(function(x){var pct=j.total?x.n*100/j.total:0,row=document.createElement("label");row.className="fp-it";
      row.innerHTML='<input type="checkbox"><span class="v"></span><span class="p"></span><span class="bar"><i></i></span>';
      var c=row.querySelector("input");c.checked=on.indexOf(x.v)>=0;row.querySelector(".v").textContent=x.v;row.querySelector(".v").title=x.v;
      row.querySelector(".p").textContent=(pct>=10?Math.round(pct):pct.toFixed(1))+"%";row.querySelector(".bar i").style.width=Math.max(1,pct)+"%";
      c.onchange=function(){var l=vals().filter(function(v){return v!==x.v});if(c.checked)l.push(x.v);$("#fp-v").value=l.join(",")};
      $("#fp-list").appendChild(row)});
    if(!(j.values||[]).length)$("#fp-n").textContent="No values in the "+(j.total||0)+" records shown"})
  .catch(function(){$("#fp-n").textContent="Values could not be loaded"})}
function open(i,anchor){cur=i;var f=i>=0?D.fields[i]:null;$("#fp-f").value=f?f.k:"clientip";$("#fp-v").value=f?f.v:"";
  $("#fp-clear").textContent=f?"Clear filter":"Cancel";pop.hidden=false;var r=anchor.getBoundingClientRect();
  pop.style.left=Math.max(8,Math.min(r.left,innerWidth-pop.offsetWidth-8))+"px";pop.style.top=(r.bottom+6)+"px";
  pop.style.maxHeight=Math.max(260,innerHeight-r.bottom-18)+"px";load();$("#fp-v").focus()}
function close(){pop.hidden=true;cur=-1}
box.querySelectorAll(".fced").forEach(function(b){b.onclick=function(e){e.stopPropagation();open(+b.dataset.i,b.parentNode)}});
document.getElementById("fadd").onclick=function(e){e.stopPropagation();open(-1,this)};
$("#fp-f").onchange=function(){$("#fp-v").value="";load()};
$("#fp-apply").onclick=function(){var v=$("#fp-v").value.trim();if(!v){if(cur>=0)go("");else close();return}go(tok($("#fp-f").value,v))};
$("#fp-clear").onclick=function(){if(cur>=0)go("");else close()};
$("#fp-v").onkeydown=function(e){if(e.key==="Enter"){e.preventDefault();$("#fp-apply").click()}if(e.key==="Escape")close()};
document.addEventListener("click",function(e){if(!pop.hidden&&!pop.contains(e.target))close()});
document.addEventListener("keydown",function(e){if(e.key==="Escape"&&!pop.hidden)close()});
})();
"""

# The row actions menu (⋮): one floating menu filled from the row's data-job.
_KB_JS = r"""
(function(){
var m=document.getElementById("kmenu");if(!m)return;var edit=m.dataset.edit==="1",cur=null;
function close(){m.hidden=true;cur=null}
function item(label,fn,href){var a=document.createElement(href?"a":"button");a.className="mi";a.textContent=label;
  if(href){a.href=href}else{a.type="button";a.onclick=function(e){e.preventDefault();var j=cur;close();fn(j)}}m.appendChild(a)}
function copy(text){if(navigator.clipboard)navigator.clipboard.writeText(text).catch(function(){prompt("Copy:",text)});else prompt("Copy:",text)}
function act(j,action){var f=document.getElementById("act-form");if(!f)return;var b=document.createElement("button");
  b.type="submit";b.name="job_id";b.value=j.id;b.setAttribute("formaction",action);b.hidden=true;f.appendChild(b);f.requestSubmit(b)}
document.addEventListener("click",function(e){var b=e.target.closest&&e.target.closest(".kb");
  if(!b){if(!m.contains(e.target))close();return}
  e.preventDefault();e.stopPropagation();var j=JSON.parse(b.closest("summary").dataset.job);
  if(cur&&cur.id===j.id){close();return}cur=j;m.innerHTML="";
  if(j.dl)item("Download PCAP",null,j.dl);
  item("Status page",null,j.key);item("JSON",null,j.key+"?format=json");
  if(j.rd){var ra=document.createElement("a");ra.className="mi";ra.textContent="Open in Raw Data";ra.href=j.rd;
    ra.target="_blank";ra.rel="noopener";m.appendChild(ra)}
  item("Copy link",function(){copy(new URL(j.key,document.baseURI).href)});
  item("Copy BPF filter",function(){copy(j.bpf)});
  if(edit){item("Re-extract…",function(x){window.srReextract&&srReextract([x])});
    if(["miss","failed","cancelled"].indexOf(j.state)>=0)item("Retry",function(x){act(x,"queue-retry")});
    if(["queued","running"].indexOf(j.state)>=0)item("Cancel",function(x){if(confirm("Cancel this job?"))act(x,"queue-cancel")})}
  m.hidden=false;var r=b.getBoundingClientRect(),w=m.offsetWidth,h=m.offsetHeight;
  m.style.left=Math.max(8,r.right-w)+"px";m.style.top=(r.bottom+4+h>innerHeight?Math.max(8,r.top-h-4):r.bottom+4)+"px"});
document.addEventListener("keydown",function(e){if(e.key==="Escape")close()});
window.addEventListener("scroll",close,true);
})();
"""


def _keep_fields(state: str | None, q: str, sort: str, desc: bool, t: str = "",
                 window: tuple[int, int] | None = None) -> str:
    """Hidden fields that let an action (and its redirect) keep the chip, quick filter, time range and
    order. `tw` is the shown window in absolute times, so "all matching" means what the page listed."""
    tw = f"{window[0]}-{window[1]}" if window else ""
    return "".join(f'<input type="hidden" name="{n}" value="{_e(v)}">' for n, v in
                   (("state", state or ""), ("q", q or ""), ("sort", sort), ("dir", "desc" if desc else "asc"),
                    ("t", t or ""), ("tw", tw)) if v or n in ("state", "q"))


def confirm_delete_page(job_ids: list[str] | None, select_all_matching: bool,
                        state: str | None, total: int,
                        base_href: str | None = None,
                        params: dict[str, str] | None = None, q: str = "",
                        window: tuple[int, int] | None = None) -> str:
    """Confirmation page for bulk deletion when JS confirm was not triggered."""
    hiddens = ['<input type="hidden" name="confirm" value="1">']
    if select_all_matching:
        hiddens.append('<input type="hidden" name="select_all_matching" value="1">')
        if state:
            hiddens.append(f'<input type="hidden" name="state" value="{_e(state)}">')
        if q:
            hiddens.append(f'<input type="hidden" name="q" value="{_e(q)}">')
        if window:
            hiddens.append(f'<input type="hidden" name="tw" value="{window[0]}-{window[1]}">')
    elif job_ids:
        for jid in job_ids:
            hiddens.append(f'<input type="hidden" name="job_id" value="{_e(jid)}">')
    for k in ("size", "page", "sort", "dir", "t"):
        if params and params.get(k):
            hiddens.append(f'<input type="hidden" name="{_e(k)}" value="{_e(params[k])}">')

    ret_url = "queue" + _url(params)
    body = (
        f'<div class="card s-miss"><h1>Confirm deletion</h1>'
        f'<div class="msg">Are you sure you want to delete <b>{total}</b> job record(s)?</div>'
        f'<p class="mut">This removes job records and their events from the database. '
        f'<b>PCAP files on disk will NEVER be deleted.</b> Jobs currently in state <code>running</code> '
        f'and jobs flagged as <code>persistent</code> are protected and will be skipped.</p>'
        f'<form method="post" action="delete">{"".join(hiddens)}'
        f'<button type="submit" class="btn-del" style="padding:6px 16px;font-size:13px">Yes, Delete {total} Job(s)</button>'
        f' <a href="{_e(ret_url)}" style="margin-left:14px">Cancel</a>'
        f'</form></div>'
    )
    return _page("Confirm delete", body, base_href=base_href, params=params)


def file_only_page(key: str, pcap: tuple[str, int], base_href: str | None = None,
                   params: dict[str, str] | None = None) -> str:
    """Alert with a PCAP on disk but no job record (sync mode): just the download."""
    body = (f'<div class="card s-done"><h1>PCAP for alert <code>{_e(key)}</code> {_badge(DONE)}'
            f'</h1><div class="msg">The PCAP is ready. This recorder keeps no job history for it '
            f"(synchronous mode or an older file).</div>"
            f'<p><a class="dlbig" href="{_e(key)}?download=1" title="Download {_e(pcap[0])}">'
            f"Download PCAP ({_e(_size(pcap[1]))})</a></p>"
            f'<div class="mut"><code>{_e(pcap[0])}</code></div></div>')
    return _page(f"PCAP {key}", body, sub="PCAP status", base_href=base_href, params=params)


def not_found_page(key: str, base_href: str | None = None,
                   params: dict[str, str] | None = None) -> str:
    body = (f'<div class="card s-unknown"><h1>No PCAP for <code>{_e(key)}</code> '
            f'{_badge("unknown")}</h1><div class="msg">This alert was never sent to the '
            f"recorder, or its record was removed.</div></div>")
    return _page("Not found", body, sub="PCAP status", base_href=base_href, params=params)


PROFILE_HELP = {
    "Name": "The alert definition's name in Sycope. An alert is matched to its profile by the definition id, not by "
            "the name, so renaming a definition breaks nothing.",
    "Filter": "The BPF filter the recorder uses for an alert of this definition. <client>, <server>, <port> and "
              "<protocol> are replaced by the values of that alert; numbers are fixed by the definition.\n\n"
              "It contains only what the definition groups by, so the PCAP can hold more than the alert (other "
              "traffic of the same hosts), never less.\n\n"
              "none: the definition counts the whole link (BPS, PPS, flows), there is no host to filter on and "
              "the recorder records nothing for it.",
    "Window": "The part of the rolling capture that is cut out, measured from the alert time: the definition's time "
              "range (its timeRange) plus SR_EXPORTER_LAG_SECONDS before (flows reach Sycope after their packets), "
              "SR_WINDOW_MARGIN_SECONDS after (clock differences). If nothing is found, the retries reach further "
              "back, up to SR_WINDOW_MAX_LAG_SECONDS.",
    "Notes": "What to know about the filter (hover a tag for the details):\n"
             "no pcap: nothing to filter on, nothing is recorded.\n"
             "broader: the PCAP holds more than the alert lists. Either the alert lists only some values (for "
             "example 10 of the servers a client scanned) and the filter does not narrow by them, or a Sycope macro "
             "could not be read and its condition is not in the filter.\n"
             "from alerts: built from other alerts; the filter is the host it groups by over its range.\n"
             "check: the definition could not be fully read; look at it in Sycope.",
    "Throttling": "Sycope's throttling of the definition: after an alert, no new alert for the same client/server "
                  "(the alert key) during this time. It does not change what is recorded.\n\n"
                  "A host with no new alert, and so no new PCAP, for a while is usually throttled in Sycope, "
                  "not missed by the recorder.",
    "Checked every": "How often Sycope runs the definition. Not used by the recorder: the alert carries its own "
                     "time.",
    "Macros": "Sycope macros ($NAME$) the definition uses, read when the profiles are built. A port or protocol "
              "inside a macro is already in the Filter; conditions on networks or roles cannot be filtered on "
              "packets.",
    "Active": "Whether the definition is enabled in Sycope. Profiles are built from active definitions; the "
              "recorder itself does not look at this.",
}


_WHO = {"clientIp": "client", "serverIp": "server", "serverPort": "port", "protocol": "protocol"}


def _dur(seconds: int | None) -> str:
    """90 -> "1 min 30 s", 360 -> "6 min", 7200 -> "2 h"."""
    if seconds is None:
        return "-"
    h, rest = divmod(int(seconds), 3600)
    m, sec = divmod(rest, 60)
    return " ".join(x for x in (f"{h} h" if h else "", f"{m} min" if m else "", f"{sec} s" if sec else "")
                    if x) or "0 s"


def _throttling_human(p: dict) -> str:
    """"1 alert per 60 min for each server": Sycope's throttling of the definition in words."""
    mins, keys = p.get("throttling_min"), [_WHO.get(k, k) for k in (p.get("alert_key") or [])]
    if mins is None and not keys:
        return "-"
    every = f"1 alert per {_dur(int(mins) * 60)}" if mins is not None else "throttled"
    return every + (f" for each {' + '.join(keys)}" if keys else " (whole definition)")


def _notes_text(p: dict) -> str:
    """The generator's notes as plain text; for a profile without a filter, say that nothing is recorded."""
    notes = list(p.get("notes", []))
    if not p.get("filter") and not any(n.startswith(("whole-link", "no packet-level")) for n in notes):
        notes.insert(0, "no filter: nothing is recorded for this definition")
    return _e("; ".join(notes)) if notes else '<span class="null">-</span>'


def _table_search(rows_selector: str, label: str) -> str:
    """A search box like the queue's that hides the table rows (CSS selector) not containing the text."""
    return (f'<div class="srch">{_LUPA}<input type="search" class="rowq" data-rows="{_e(rows_selector)}" '
            f'placeholder="Search" aria-label="{_e(label)}" title="{_e(label)}"></div>')


_ROWQ_JS = ('<script>document.querySelectorAll("input.rowq").forEach(function(q){q.oninput=function(){'
            'var v=q.value.trim().toLowerCase();document.querySelectorAll(q.dataset.rows).forEach(function(r){'
            'r.hidden=!!v&&r.textContent.toLowerCase().indexOf(v)<0})}})</script>')


def _profiles_views(rows: list[dict]) -> str:
    """The profiles in two views of the same rows: what gets recorded (filter, window, notes) and the
    definitions' Sycope settings (throttling, interval, macros). Radio buttons switch them with CSS only;
    a script remembers the choice and filters by name."""
    def table(cls: str, head: list, cells) -> str:
        th = "".join(f"<th>{_e(h)}{_info(PROFILE_HELP[h])}</th>" for h in head)
        tr = "".join(f'<tr data-n="{_e(str(p["name"] or "").lower())}">' + "".join(f"<td>{c}</td>" for c in cells(p))
                     + "</tr>" for p in rows)
        return f'<div class="grid pv-t {cls}"><table><tr>{th}</tr>{tr}</table></div>'
    pcap = table("pv-pcap", ["Name", "Filter", "Window", "Notes"], lambda p: [
        _e(p["name"]),
        f'<code>{_e(p["filter"])}</code>' if p["filter"] else '<span class="mut">none</span>',
        (f'{_e(_dur(p["before_s"]))} before, {_e(_dur(p["after_s"]))} after' if p["filter"] and p.get("before_s")
         else '<span class="mut">-</span>'),
        _notes_text(p)])
    syc = table("pv-syc", ["Name", "Throttling", "Checked every", "Macros", "Active"], lambda p: [
        _e(p["name"]), _e(_throttling_human(p)), _e(_dur(p["interval_s"]) if p["interval_s"] else "-"),
        _e(", ".join(p["macros"]) or "-"), _e("yes" if p["active"] else "no")])
    return ('<div class="pv">'
            '<input type="radio" name="pv" id="pv-1" checked><input type="radio" name="pv" id="pv-2">'
            '<div class="chiprow pv-bar"><div class="chips"><label class="chip" for="pv-1">What gets recorded</label>'
            '<label class="chip" for="pv-2">Sycope settings</label></div>'
            + _table_search(".pv tr[data-n]", "Search the profiles (name, filter, notes, throttling)") + '</div>'
            '<p class="mut pv-cap pv-pcap">What decides the PCAP of an alert: the BPF filter (&lt;client&gt;, '
            '&lt;server&gt;, &lt;port&gt;, &lt;protocol&gt; are the values of that alert) and the time window around '
            'the alert time.</p>'
            '<p class="mut pv-cap pv-syc">How the definitions are set up in Sycope. None of this changes what is '
            'recorded: it decides how often Sycope raises an alert (and so how often a PCAP is made).</p>'
            f'{pcap}{syc}</div>'
            '<script>(function(){var K="srProfView",a=document.getElementById("pv-1"),b=document.getElementById("pv-2");'
            'if(!a)return;try{if(localStorage.getItem(K)==="2")b.checked=true}catch(e){}'
            'a.onchange=b.onchange=function(){try{localStorage.setItem(K,b.checked?"2":"1")}catch(e){}}})();</script>'
            + _ROWQ_JS)


def _static_text(static: dict) -> str:
    return "; ".join(f"{k} in {v}" for k, v in static.items()) or "-"


def _key_of(job_id: str) -> str:
    """The alert key inside a job file name (`<date>_<time>_<key>.pcap`), the link of the status page."""
    return re.sub(r"^\d{8}_\d{6}_|\.pcap$", "", str(job_id))


def _dot(status: str) -> str:
    return f'<span class="dot {_e(status)}" title="{_e(status)}"></span>'


_STAT = {"ok": ("st-ok", "&#9650;", "OK"), "warn": ("st-warn", "&#9632;", "WARN"),
         "fail": ("st-fail", "&#9660;", "FAIL"), "unknown": ("st-unk", "&ndash;", "N/A")}


def _stat(status: str, label: str | None = None) -> str:
    """A status the way Sycope's service table shows it: a coloured mono word with a marker."""
    cls, mark, word = _STAT.get(status, _STAT["unknown"])
    return f'<span class="st {cls}">{mark} {_e((label or word).upper())}</span>'


def _usage(used: int | None, total: int | None, free: int | None, pct: int | None,
           floor: int | None = None) -> tuple[str, str]:
    """(bar with "used X of Y total ... Z free", percentage) like Sycope's disk drive table. `floor` (bytes)
    marks where the free space reaches SR_MIN_FREE_BYTES: extractions are refused beyond the mark."""
    if total is None:
        return '<span class="mut">not available</span>', ""
    level = "hi" if (pct or 0) >= 90 else ("mid" if (pct or 0) >= 80 else "")
    mark = ""
    if floor and total and floor < total:
        at = (total - floor) * 100 / total
        mark = (f'<b class="umark" style="left:{at:.2f}%" title="Extractions stop here: less than '
                f'{_e(_bytes(floor))} free (SR_MIN_FREE_BYTES)"></b>')
    bar = (f'<div class="ub"><div class="ubar"><i class="{level}" style="width:{min(100, max(0, pct or 0))}%"></i>{mark}</div>'
           f'<div class="utext"><span>used <b>{_e(_bytes(used))}</b> of <b>{_e(_bytes(total))}</b> total</span>'
           + (f'<span><b>{_e(_bytes(free))}</b> free</span>' if free is not None else "") + '</div></div>')
    return bar, f"{pct} %" if pct is not None else ""


def _tiles(seconds: int | None) -> str:
    """Uptime as Sycope's green day/hour/minute tiles."""
    if seconds is None:
        return '<span class="mut">unknown</span>'
    d, rest = divmod(int(seconds), 86400)
    h, m = rest // 3600, rest % 3600 // 60
    tile = '<div><b>{:02d}</b><span>{}</span></div>'
    return (f'<div class="tiles">{tile.format(d, "days")}<em>:</em>{tile.format(h, "hours")}<em>:</em>'
            f'{tile.format(m, "minutes")}</div>')


def _bytes(n: float | None) -> str:
    if n is None:
        return ""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _age(seconds: int | None) -> str:
    if seconds is None:
        return ""
    if seconds < 120:
        return f"{seconds} s ago"
    return f"{seconds // 60} min ago" if seconds < 7200 else f"{seconds // 3600} h ago"


_UPLOAD_JS = (
    '<script>(function(){var b=document.getElementById("pf-go"),f=document.getElementById("pf"),'
    's=document.getElementById("pf-st");if(!b)return;b.onclick=function(){'
    'if(!f.files.length){s.textContent="Choose a profiles.json first.";return}'
    's.textContent="Checking...";f.files[0].text().then(function(t){'
    'return fetch("profiles-upload",{method:"POST",headers:{"Content-Type":"application/json"},body:t})})'
    '.then(function(r){return r.json()}).then(function(j){'
    'if(j.errors&&j.errors.length){s.textContent="Rejected: "+j.errors.slice(0,8).join(" | ");return}'
    'location.href="profiles?review="+j.token}).catch(function(e){s.textContent="Failed: "+e})}})();</script>')


def _import_block(im: dict) -> str:
    """What the import read from Sycope: definitions, and every macro with its status."""
    macros = im.get("macros", {})
    bad = [n for n, m in macros.items() if not m["readable"]]
    rows = []
    for n, m in sorted(macros.items()):
        lk = "; ".join(f'{x["lookup"]}: {x["networks"]} network(s)' + ("" if x["status"] == "ok" else f' ({x["status"]})')
                       for x in m["lookups"])
        rows.append([_dot("ok" if m["readable"] else "warn"), f"<code>${_e(n)}$</code>", _e(m["status"]), _e(lk or "-")])
    table = _grid(["", "Macro", "Read", "Lookups"], rows) if rows else '<div class="mut">The definitions use no macros.</div>'
    warn = (f'<div class="warnbox">&#9888; {len(bad)} macro(s) could not be read ({_e(", ".join("$" + b + "$" for b in bad))}): '
            f'their profiles keep a broader filter.</div>' if bad else "")
    at = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(im["at"]))
    return (f'<p class="mut">Read from {_e(im["source"])} at {_e(at)} UTC: {_e(im["definitions"])} alert '
            f'definitions, {_e(im["profiles"])} profiles built, {len(macros)} macros ({len(macros) - len(bad)} read).</p>'
            f'{warn}{table}')


_CFG_JS = (
    '<script>(function(){var pw=document.getElementById("cfg-pw"),st=document.getElementById("cfg-st"),'
    'dl=document.getElementById("cfg-dl"),up=document.getElementById("cfg-up"),f=document.getElementById("cfg-file");'
    'if(!dl)return;function say(t){st.textContent=t}'
    'function post(url,body){return fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},'
    'body:JSON.stringify(body),credentials:"same-origin"})}'
    'dl.onclick=function(){if(!pw.value){say("Enter the configuration password first.");return}say("Preparing...");'
    'post("configuration-download",{password:pw.value}).then(function(r){'
    'if(!r.ok)return r.json().then(function(j){say((j.errors||["Refused"])[0])});'
    'return r.blob().then(function(b){var a=document.createElement("a");a.href=URL.createObjectURL(b);'
    'a.download="recorder-config.json";document.body.appendChild(a);a.click();a.remove();say("Downloaded.")})})'
    '.catch(function(x){say("Failed: "+x)})};'
    'up.onclick=function(){if(!pw.value){say("Enter the configuration password first.");return}'
    'if(!f.files.length){say("Choose a configuration JSON first.");return}say("Checking...");'
    'f.files[0].text().then(function(t){var c;try{c=JSON.parse(t)}catch(x){say("Not valid JSON: "+x);return}'
    'return post("configuration-upload",{password:pw.value,config:c}).then(function(r){return r.json()})'
    '.then(function(j){if(j.errors&&j.errors.length){say("Rejected: "+j.errors.slice(0,8).join(" | "));return}'
    'location.href="configuration?review="+j.token})}).catch(function(x){say("Failed: "+x)})}})();</script>')


def _config_review(rv: dict) -> str:
    """The staged configuration: what changes, warnings, and the apply form (asks for the password)."""
    rows = [[_e(c["key"]), _e(c["old"]), _e(c["new"])] for c in rv.get("changes", [])]
    table = (_grid(["Setting", "Now", "After"], rows) if rows
             else '<div class="mut">No differences from the running configuration.</div>')
    warns = "".join(f'<div class="warnbox">&#9888; {_e(w)}</div>' for w in rv.get("warnings", []))
    return (f'<div class="card s-queued" style="margin:8px 0"><h2>Uploaded configuration: review</h2>'
            f'<p>{len(rows)} setting(s) change. Applying stores them as an override of the environment and '
            f'<b>reloads the service</b> (a few seconds; a running extraction is re-queued).</p>{warns}{table}'
            f'<form method="post" action="configuration-apply" style="margin-top:10px">'
            f'<input type="hidden" name="token" value="{_e(rv["token"])}">'
            f'<input type="password" name="password" placeholder="configuration password" autocomplete="off" required> '
            f'<button type="submit" class="btn-del" style="background:var(--blue)">Apply and reload</button> '
            f'<a href="configuration">Cancel</a></form></div>')


def _review_block(rv: dict) -> str:
    """The staged upload: what was found, what would change, and the apply/cancel buttons."""
    errs = "".join(f'<div class="warnbox" style="border-color:var(--bad);background:var(--badbg)">&#10007; {_e(x)}</div>'
                   for x in rv["errors"])
    warns = "".join(f'<div class="warnbox">&#9888; {_e(x)}</div>' for x in rv["warnings"])
    df = rv.get("diff") or {"added": [], "removed": [], "changed": []}
    rows = ([[_badge("done"), _e(n), "added"] for n in df["added"]]
            + [[_badge("failed"), _e(n), "removed"] for n in df["removed"]]
            + [[_badge("queued"), _e(c["name"]),
                  _e(("changes behaviour: " + ", ".join(c["fields"]) if c["fields"] else "")
                     + ("; " if c["fields"] and c["informational"] else "")
                     + ("informational only (not used): " + ", ".join(c["informational"]) if c["informational"] else ""))]
                 for c in df["changed"]])
    table = _grid(["", "Profile", "Change"], rows[:200]) if rows else '<div class="mut">No differences from the active profiles.</div>'
    ok = not rv["errors"]
    apply_btn = (f'<form method="post" action="profiles-apply" style="display:inline">'
                 f'<input type="hidden" name="token" value="{_e(rv["token"])}">'
                 f'<button type="submit" class="btn-del" style="background:var(--blue)">Apply {rv["count"]} profiles</button></form> '
                 if ok else "")
    return (f'<div class="card s-queued" style="margin:8px 0"><h2>Uploaded file: review</h2>'
            f'<p>{"The file is valid." if ok else "The file has errors and cannot be applied."} '
            f'{rv["count"]} profiles; {len(df["added"])} added, {len(df["removed"])} removed, '
            f'{len(df["changed"])} changed.</p>{_import_block(rv["import"]) if rv.get("import") else ""}'
            f'{errs}{warns}{table}'
            f'<p style="margin-top:10px">{apply_btn}<a href="profiles">Cancel</a></p></div>')


def system_page(d: dict, editable: bool = False, bundle: bool = False, msg: str | None = None,
                base_href: str | None = None, review: dict | None = None, view: str = "status") -> str:
    """System status: instance, checks per module (Sycope-style status dots), capture and storage,
    queue, profiles (with a reload when edits are enabled), effective configuration."""
    banner = _toast(msg)
    warn = ("".join(f'<div class="warnbox">&#9888; {_e(w)}</div>' for w in d["warnings"]))
    prof = d["profiles"]
    checks = _grid(["Status", "Module", "Check", "Detail"], [
        [_stat(c["status"]), _e(c["module"]), _e(c["name"]), _e(c["detail"])] for c in
        sorted(d["checks"], key=lambda c: (c["module"], c["name"]))])
    r, a = d["rolling"], d["alerts"]
    need = d["need_minutes"]
    ret_ok = r["retention_minutes"] is not None and (need is None or r["retention_minutes"] >= need)
    if not r["reported"]:      # the worker has not listed the rolling tree yet: neither ok nor a problem
        roll_row = [_stat("unknown"), "Rolling buffer history", _e("not reported by the worker yet"), ""]
    else:
        roll_row = [_stat("ok" if ret_ok and not r["stale"] else "warn"), "Rolling buffer history",
                    _e(f'{r["retention_minutes"]} min' if r["retention_minutes"] is not None else "no files"),
                    _e(("" if r["files"] is None else f'{r["files"]} files, ')
                       + f'newest started {_age(r["newest_age_seconds"]) or "never"}'
                       + (f'; longest profile needs about {need} min' if need else "")
                       + (f'; reported by the worker {_age(r["reported_age_seconds"])}' if not r["stale"] else
                          f' (stale: the worker has not reported for {r["reported_age_seconds"]} s)'))]
    storage = _grid(["Status", "Area", "Value",
                     ("Detail", "Rolling buffer history: how many minutes of capture are on disk (age of the oldest "
                      "closed file). It must be at least what the longest profile needs (range + lag + chunk): below "
                      "that, alerts of that profile can miss. It shrinks when traffic grows, because the buffer is "
                      "limited by size (n2disk --disk-limit), not time.\nAlert PCAPs: extracted evidence; never "
                      "deleted unless SR_RETENTION_* is set.")], [
        roll_row,
        [_stat("ok"), "Alert PCAPs", _e(a["files"]), _e(_bytes(a["bytes"]))],
        [_stat("ok"), "Jobs database", _e(_bytes(d["db_bytes"])), _e(f'{sum(d["queue"].values())} jobs')]])
    q = d["queue"]
    out = d["outcomes"]
    queue = _grid(["Queued", "Running", "Done", "Miss", "Failed", "Cancelled"], [[
        _e(q.get(k, 0)) for k in (QUEUED, RUNNING, DONE, MISS, FAILED, CANCELLED)]]) if q else ""
    outcomes = _grid([f"Outcome (since {_t(d['since'])} UTC)" if d.get("since") else "Outcome", "Count"], [[_e(k), _e(v)] for k, v in sorted(out.items())])
    act = prof.get("active", {})
    src = {"uploaded": "uploaded file", "file": "mounted file", "none": "none"}.get(act.get("source"), "")
    revert = ('<form method="post" action="profiles-revert" style="display:inline" '
              'onsubmit="return confirm(\'Go back to the mounted profiles file?\')">'
              '<button type="submit" class="btn-del">Remove uploaded profiles</button></form> '
              if act.get("source") == "uploaded" else "")
    syc = prof.get("sycope", {})
    sync_btn = ('<form method="post" action="profiles-sync" style="display:inline" '
                'onsubmit="this.querySelector(\'button\').textContent=\'Reading Sycope...\'">'
                '<button type="submit" class="btn-del" style="background:var(--blue)" '
                'title="Reads alert definitions and macros from Sycope and shows what would change">'
                'Rebuild from Sycope</button></form> ' if syc.get("configured") else
                '<span class="mut">Rebuild from Sycope needs SR_SYCOPE_URL, SR_SYCOPE_USER, SR_SYCOPE_PASSWORD</span> ')
    reload_btn = (
        '<form method="post" action="reload-profiles" style="display:inline">'
        '<button type="submit" class="btn-del" style="background:var(--blue)">Reload profiles from file</button></form> '
        + sync_btn +
        '<input type="file" id="pf" accept=".json,application/json"> '
        '<button type="button" id="pf-go" class="btn-del" style="background:var(--blue)">Check uploaded file</button> '
        + revert + '<span class="mut" id="pf-st"></span>'
        if editable else '<span class="mut">Uploading and reloading need SR_QUEUE_EDIT=true</span>')
    download = (' <a class="dlbig" style="padding:4px 12px" href="profiles-file">Download profiles.json</a>'
                if prof["count"] else "")
    mt = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(prof["mtime"])) if prof["mtime"] else ""
    profiles = _profiles_views(prof["rows"]) if prof["rows"] else '<div class="empty">No profiles loaded.</div>'
    cfg_rows = [[f'<code>SR_{_e(r["key"].upper())}</code>{_info(CONFIG_HELP.get(r["key"], ""))}'
                 + (' <span class="badge b-unknown">locked</span>' if r["locked"] else ""),
                 _e(r["value"]), _e(r["default"]), _e(r["source"])] for r in d["config_rows"]]
    cfg = (f'<div class="chiprow cfg-bar">{_table_search(".cfg-t tr:not(:first-child)", "Search the settings (name, value, source)")}</div>'
           f'<div class="cfg-t">{_grid(["Setting", "Value", "Default", "Source"], cfg_rows)}</div>{_ROWQ_JS}')
    logs = (' <a class="dlbig" href="logs">Generate logs</a>' if bundle else
            ' <span class="mut">Debug logs need SR_DEBUG_BUNDLE=true</span>')
    now = time.time()
    wrows = []
    for w in d.get("workers", []):
        hb = None if w.get("heartbeat") is None else int(now - w["heartbeat"])
        dur = None if not w.get("step_started") else int(now - w["step_started"])
        job = (f'<a href="{_e(_key_of(w["job_id"]))}">{_e(w["job_id"])}</a>' if w.get("job_id") else "")
        status = ("ok" if w.get("state") in (WORKER_IDLE, WORKER_BUSY, WORKER_RUNNING)
                  else ("warn" if w.get("state") == WORKER_PAUSED else "fail"))
        if not d["worker"]["alive"]:   # a slot row is written only on state changes: it follows main's heartbeat
            status = "fail"
        if w["slot"] == MAIN_SLOT:
            beat = f"{hb} s ago" if hb is not None else "never"
        elif w.get("state") == WORKER_IDLE:  # the row's last update: when this slot became idle
            beat = f'idle for {_age(hb).replace(" ago", "")}' if hb is not None else "idle"
        else:
            beat = ""                   # busy: the step and the time in it say what it is doing
        wrows.append([_stat(status, w.get("state") or status), _e(w["slot"]), _e(w.get("state")), job, _e(w.get("step") or ""),
                      _e(f"{dur} s" if dur is not None else ""), _e(w.get("child_pid") or ""), _e(beat)])
    pause_btn = ((f'<form method="post" action="worker-pause" style="display:inline">'
                  f'<input type="hidden" name="paused" value="{"0" if d["paused"] else "1"}">'
                  f'<button type="submit" class="btn-del">{"Resume" if d["paused"] else "Pause"} worker</button></form>')
                 if editable else '<span class="mut">Pause/resume needs SR_QUEUE_EDIT=true</span>')
    workers = (_grid(["Status", "Slot", "State", "Job", "Step", "In step", "npcapextract PID", "Heartbeat / idle"], wrows)
               if wrows else '<div class="empty">The worker has not started yet.</div>')
    host = d.get("host") or {}
    disks = d.get("disks") or []
    cpu = " ".join(x for x in (f'{host["cpus"]} CPUs' if host.get("cpus") else "", host.get("cpu_model") or "") if x)
    info = "".join(_kv(k, v) for k, v in (
        ("Version", _e(d["version"])), ("Time zone", _e(d["tz"])), ("CPU", _cell(cpu)),
        ("Total RAM", _cell(_bytes(host.get("mem_total")))),
        ("Overall", _stat({"ok": "ok", "warn": "warn", "fail": "fail"}.get(d["overall"], "warn"))),
        ("Worker", _stat("ok" if d["worker"]["alive"] and not d["paused"] else ("warn" if d["paused"] else "fail"),
                         d["worker"]["state"] + (" (paused)" if d["paused"] else ""))),
        ("Last webhook", _e(_age(d["seconds_since_last_webhook"]) or "never")),
        ("Last success", _e(_age(d["seconds_since_last_success"]) or "never"))))
    worker_up = _age(d["uptime"]["worker"]).replace(" ago", "")
    uptime = (f'{_tiles(d["uptime"]["web"])}'
              f'<div class="mut tilecap">web service{f"; worker up {_e(worker_up)}" if worker_up else ""}</div>')
    res = []
    if host.get("mem_total"):
        pct = round((host.get("mem_used") or 0) * 100 / host["mem_total"])
        bar, p = _usage(host.get("mem_used"), host["mem_total"], None, pct)
        res.append(f'<div class="res"><h4><i class="rd m"></i>Memory (host)</h4>{bar}<span class="rp">{p}</span></div>')
    if host.get("load1") is not None and host.get("cpus"):
        lp = min(100, round(host["load1"] * 100 / host["cpus"]))
        res.append(f'<div class="res"><h4><i class="rd c"></i>CPU load (1 min average {host["load1"]:.2f})</h4>'
                   f'<div class="ubar"><i class="{"hi" if lp >= 90 else ("mid" if lp >= 80 else "")}" '
                   f'style="width:{lp}%"></i></div><span class="rp">{lp} %</span></div>')
    ours = {"Alert PCAPs": f'Alert PCAPs {_bytes(d["alerts"]["bytes"])} ({d["alerts"]["files"]} files)',
            "Recorder state": f'Jobs database {_bytes(d["db_bytes"]) or "-"}',
            "Rolling buffer (n2disk)": "Rolling buffer: size not measured" + (
                f', holds {d["rolling"]["retention_minutes"]} min' if d["rolling"].get("retention_minutes") is not None
                else "")}
    drows = []
    for dk in disks:
        floor = d.get("min_free_bytes") if "Alert PCAPs" in dk["names"] else None
        bar, p = _usage(dk["used"], dk["total"], dk["free"], dk["pct"], floor)
        drows.append([f'{_e(" + ".join(dk["names"]))}<span class="idl mono">{_e(", ".join(dk["paths"]))}</span>',
                      bar, f'<span class="upct">{_e(p)}</span>',
                      "".join(f'<span class="dline">{_e(ours[n])}</span>' for n in dk["names"] if n in ours)])
    disk_grid = (_grid(["Name", "Usage", "", "Recorder data on it"], drows).replace('<table>', '<table class="dtab">', 1)
                 if drows else '<div class="empty">No volumes found.</div>')
    status_body = (
        f'{banner}<h1 class="ptitle">System status</h1>{warn}'
        f'<div class="srow"><div class="card"><h3 class="ct">System information</h3><div class="kv">{info}</div></div>'
        f'<div class="card"><h3 class="ct">Uptime</h3>{uptime}</div>'
        f'<div class="card"><h3 class="ct">Resources</h3>{"".join(res) or _cell("")}</div></div>'
        f'<div class="card"><h3 class="ct">Disk drives</h3>{disk_grid}</div>'
        f'<div class="card"><h3 class="ct">Checks</h3>{checks}</div>'
        f'<div class="card"><div class="cth"><h3 class="ct">Workers</h3>{pause_btn}</div>{workers}</div>'
        f'<div class="card"><h3 class="ct">Capture and storage</h3>{storage}</div>'
        f'<div class="card"><h3 class="ct">Queue</h3>{queue}<div style="height:8px"></div>{outcomes}</div>'
        f'<div class="card"><div class="cth"><h3 class="ct">System logs</h3>{logs}</div>'
        f'<div class="mut">A zip of what the api container sees: recent logs (with every npcapextract error), the job '
        f'table with history, checks, settings with masked secrets, disk and a rolling summary. No host journal, '
        f'no PCAP content.</div></div>')
    profiles_body = (
        f'{banner}<div class="card" id="profiles"><h1>Recorder: profiles ({prof["count"]})</h1>'
        f'<div class="mut" style="margin-bottom:8px">Active: {_e(src)} {_e(prof["file"] or "not configured")}'
        f'{" - file changed " + _e(mt) + " UTC" if mt else ""}'
        f'{" - sha " + _e(act["sha"]) if act.get("sha") else ""}</div>'
        f'<p>{reload_btn}{download}</p>{_review_block(review) if review and view == "profiles" else ""}{profiles}</div>')
    if d.get("config_enabled"):
        cfg_ctl = ('<input type="password" id="cfg-pw" placeholder="configuration password" autocomplete="off"> '
                   '<button type="button" id="cfg-dl" class="btn-del" style="background:var(--blue)">Download configuration</button> '
                   '<input type="file" id="cfg-file" accept=".json,application/json"> '
                   '<button type="button" id="cfg-up" class="btn-del" style="background:var(--blue)">Check uploaded file</button> '
                   '<form method="post" action="configuration-revert" style="display:inline" '
                   'onsubmit="return confirm(\'Remove the uploaded configuration and reload?\')">'
                   '<input type="password" name="password" placeholder="password" autocomplete="off" size="10" required> '
                   '<button type="submit" class="btn-del">Remove uploaded configuration</button></form> '
                   '<span class="mut" id="cfg-st"></span>')
    else:
        cfg_ctl = '<span class="mut">Download and upload need SR_CONFIG_PASSWORD to be set in the environment.</span>'
    config_body = (f'{banner}<div class="card"><h1>Recorder: configuration</h1>'
                   f'<div class="mut" style="margin-bottom:8px">Effective settings. Source: environment (.env), '
                   f'uploaded (override stored in the state directory) or built-in default. Secrets are masked here '
                   f'and included in the downloaded file.</div><p>{cfg_ctl}</p>'
                   f'{_config_review(review) if review and review.get("changes") is not None and view == "configuration" else ""}'
                   f'{cfg}</div>')
    body, sub, title = {"profiles": (profiles_body + _UPLOAD_JS, "profiles", "Recorder profiles"),
                        "configuration": (config_body + _CFG_JS, "configuration", "Recorder configuration")
                        }.get(view, (status_body, "system status", "Recorder system"))
    return _page(title, body, refresh=None, sub=sub, base_href=base_href, bundle=bundle, active=view,
                 auto_refresh=view not in ("profiles", "configuration"))
