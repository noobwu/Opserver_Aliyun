﻿/*! jquery-visibility v1.0.12 | MIT license | http://mths.be/visibility */
!function (e, i) { "function" == typeof define && define.amd ? define(["jquery"], function (t) { return i(e, t) }) : "object" == typeof exports ? module.exports = i(e, require("jquery")) : i(e, jQuery) }(this, function (e, i, t) { "use strict"; function o() { "hidden" !== n && (r.hidden = f.pageVisibility ? r[n] : t) } for (var n, u, r = e.document, s = ["webkit", "o", "ms", "moz", ""], f = i.support || {}, c = ("onfocusin" in r && "hasFocus" in r ? "focusin focusout" : "focus blur") ; (u = s.pop()) !== t;) if (n = (u ? u + "H" : "h") + "idden", f.pageVisibility = r[n] !== t, f.pageVisibility) { c = u + "visibilitychange"; break } o(), i(/blur$/.test(c) ? e : r).on(c, function (e) { var u = e.type, s = e.originalEvent; if (s) { var f = s.toElement; (!/^focus./.test(u) || f === t && s.fromElement === t && s.relatedTarget === t) && i(r).triggerHandler(n && r[n] || /^(?:blur|focusout)$/.test(u) ? "hide" : "show"), o() } }) });