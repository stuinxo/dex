/* Standalone pure-JS QR SVG generator (Byte mode, no external deps). */
(function (global) {
  "use strict";

  var EXP = new Array(256);
  var LOG = new Array(256);
  for (var i = 0; i < 8; i++) EXP[i] = 1 << i;
  for (var i = 8; i < 256; i++) EXP[i] = EXP[i - 4] ^ EXP[i - 5] ^ EXP[i - 6] ^ EXP[i - 8];
  for (var i = 0; i < 255; i++) LOG[EXP[i]] = i;

  function gexp(n) {
    while (n < 0) n += 255;
    while (n >= 256) n -= 255;
    return EXP[n];
  }
  function glog(n) {
    if (n < 1) throw new Error("glog");
    return LOG[n];
  }

  function Poly(num, shift) {
    var off = 0;
    while (off < num.length && num[off] === 0) off++;
    this.num = new Array(num.length - off + shift);
    for (var i = 0; i < num.length - off; i++) this.num[i] = num[i + off];
    for (var j = num.length - off; j < this.num.length; j++) this.num[j] = 0;
  }
  Poly.prototype.mul = function (e) {
    var n = new Array(this.num.length + e.num.length - 1).fill(0);
    for (var i = 0; i < this.num.length; i++) {
      for (var j = 0; j < e.num.length; j++) {
        n[i + j] ^= gexp(glog(this.num[i]) + glog(e.num[j]));
      }
    }
    return new Poly(n, 0);
  };
  Poly.prototype.mod = function (e) {
    if (this.num.length - e.num.length < 0) return this;
    var ratio = glog(this.num[0]) - glog(e.num[0]);
    var n = this.num.slice();
    for (var i = 0; i < e.num.length; i++) n[i] ^= gexp(glog(e.num[i]) + ratio);
    return new Poly(n, 0).mod(e);
  };

  function ecPoly(len) {
    var a = new Poly([1], 0);
    for (var i = 0; i < len; i++) a = a.mul(new Poly([1, gexp(i)], 0));
    return a;
  }

  // Error Correction Level L RS block specs for versions 1..20: [count, totalCodewords, dataCodewords, ...]
  var RS_L = [
    [1, 26, 19], [1, 44, 34], [1, 70, 55], [1, 100, 80], [1, 134, 108],
    [2, 86, 68], [2, 98, 78], [2, 121, 97], [2, 146, 116], [2, 86, 68, 2, 87, 69],
    [4, 101, 81], [2, 116, 92, 2, 117, 93], [4, 133, 107], [3, 145, 115, 1, 146, 116],
    [5, 109, 87, 1, 110, 88], [5, 122, 98, 1, 123, 99], [1, 135, 107, 5, 136, 108],
    [5, 150, 120, 1, 151, 121], [3, 141, 113, 4, 142, 114], [3, 135, 107, 5, 136, 108]
  ];
  var ALIGN = [
    [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54],
    [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74],
    [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90]
  ];

  function rsBlocksFor(ver) {
    var spec = RS_L[ver - 1];
    var out = [];
    for (var i = 0; i < spec.length; i += 3) {
      for (var c = 0; c < spec[i]; c++) out.push({ total: spec[i + 1], data: spec[i + 2] });
    }
    return out;
  }

  function bchDigit(d) {
    var n = 0;
    while (d !== 0) { n++; d >>>= 1; }
    return n;
  }
  function bchTypeInfo(d) {
    var r = d << 10;
    while (bchDigit(r) - bchDigit(1335) >= 0) r ^= 1335 << (bchDigit(r) - bchDigit(1335));
    return ((d << 10) | r) ^ 21522;
  }
  function bchTypeNum(d) {
    var r = d << 12;
    while (bchDigit(r) - bchDigit(7973) >= 0) r ^= 7973 << (bchDigit(r) - bchDigit(7973));
    return (d << 12) | r;
  }

  function encodeQR(text) {
    var utf8 = new TextEncoder().encode(text);
    var ver = 1;
    var blocks;
    for (; ver <= RS_L.length; ver++) {
      blocks = rsBlocksFor(ver);
      var cap = blocks.reduce(function (s, b) { return s + b.data; }, 0);
      var lenBits = ver < 10 ? 8 : 16;
      if (4 + lenBits + utf8.length * 8 <= cap * 8) break;
    }
    if (ver > RS_L.length) throw new Error("QR payload too long");

    var bits = [];
    function put(val, len) {
      for (var i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
    }
    put(4, 4); // byte mode
    put(utf8.length, ver < 10 ? 8 : 16);
    for (var i = 0; i < utf8.length; i++) put(utf8[i], 8);

    var totalDataBytes = blocks.reduce(function (s, b) { return s + b.data; }, 0);
    if (bits.length + 4 <= totalDataBytes * 8) put(0, 4);
    while (bits.length % 8 !== 0) bits.push(0);
    var pad = [236, 17];
    var pi = 0;
    while (bits.length < totalDataBytes * 8) {
      put(pad[pi % 2], 8);
      pi++;
    }

    var bytes = new Array(totalDataBytes);
    for (var i = 0; i < totalDataBytes; i++) {
      var v = 0;
      for (var b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
      bytes[i] = v;
    }

    var dc = [], ec = [], off = 0, maxD = 0, maxE = 0;
    for (var r = 0; r < blocks.length; r++) {
      var dLen = blocks[r].data;
      var eLen = blocks[r].total - dLen;
      if (dLen > maxD) maxD = dLen;
      if (eLen > maxE) maxE = eLen;
      var slice = bytes.slice(off, off + dLen);
      off += dLen;
      dc.push(slice);
      var gp = ecPoly(eLen);
      var rem = new Poly(slice, gp.num.length - 1).mod(gp);
      var eArr = new Array(gp.num.length - 1);
      for (var j = 0; j < eArr.length; j++) {
        var idx = j + rem.num.length - eArr.length;
        eArr[j] = idx >= 0 ? rem.num[idx] : 0;
      }
      ec.push(eArr);
    }

    var data = [];
    for (var i = 0; i < maxD; i++) for (var r = 0; r < blocks.length; r++) if (i < dc[r].length) data.push(dc[r][i]);
    for (var i = 0; i < maxE; i++) for (var r = 0; r < blocks.length; r++) if (i < ec[r].length) data.push(ec[r][i]);

    var size = ver * 4 + 17;
    var mat = Array.from({ length: size }, function () { return new Array(size).fill(null); });

    function finder(r0, c0) {
      for (var r = -1; r <= 7; r++) {
        if (r0 + r < 0 || r0 + r >= size) continue;
        for (var c = -1; c <= 7; c++) {
          if (c0 + c < 0 || c0 + c >= size) continue;
          var dark = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
            (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
            (r >= 2 && r <= 4 && c >= 2 && c <= 4);
          mat[r0 + r][c0 + c] = dark;
        }
      }
    }
    finder(0, 0);
    finder(size - 7, 0);
    finder(0, size - 7);

    var ap = ALIGN[ver - 1];
    for (var i = 0; i < ap.length; i++) {
      for (var j = 0; j < ap.length; j++) {
        var rr = ap[i], cc = ap[j];
        if (mat[rr][cc] !== null) continue;
        for (var dr = -2; dr <= 2; dr++) for (var dc2 = -2; dc2 <= 2; dc2++) {
          mat[rr + dr][cc + dc2] = (Math.abs(dr) === 2 || Math.abs(dc2) === 2 || (dr === 0 && dc2 === 0));
        }
      }
    }
    for (var i = 8; i < size - 8; i++) {
      if (mat[i][6] === null) mat[i][6] = (i % 2 === 0);
      if (mat[6][i] === null) mat[6][i] = (i % 2 === 0);
    }

    var mask = 0; // mask pattern 0: (r+c)%2 === 0
    var tInfo = bchTypeInfo((1 << 3) | mask); // ECL L = 1
    for (var i = 0; i < 15; i++) {
      var bit = ((tInfo >>> i) & 1) === 1;
      if (i < 6) mat[i][8] = bit; else if (i < 8) mat[i + 1][8] = bit; else mat[size - 15 + i][8] = bit;
      if (i < 8) mat[8][size - i - 1] = bit; else if (i < 9) mat[8][15 - i] = bit; else mat[8][14 - i] = bit;
    }
    mat[size - 8][8] = true;

    if (ver >= 7) {
      var tNum = bchTypeNum(ver);
      for (var i = 0; i < 18; i++) {
        var bit = ((tNum >>> i) & 1) === 1;
        mat[Math.floor(i / 3)][(i % 3) + size - 11] = bit;
        mat[(i % 3) + size - 11][Math.floor(i / 3)] = bit;
      }
    }

    var dir = -1, row = size - 1, bi = 0, bitIdx = 7;
    for (var col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      while (true) {
        for (var c = 0; c < 2; c++) {
          if (mat[row][col - c] === null) {
            var d = bi < data.length && (((data[bi] >>> bitIdx) & 1) === 1);
            if ((row + (col - c)) % 2 === 0) d = !d;
            mat[row][col - c] = d;
            bitIdx--;
            if (bitIdx < 0) { bi++; bitIdx = 7; }
          }
        }
        row += dir;
        if (row < 0 || row >= size) { row -= dir; dir = -dir; break; }
      }
    }
    return mat;
  }

  global.DexQR = {
    createSVG: function (text, sizePx) {
      var mat = encodeQR(text);
      var n = mat.length;
      var q = 2;
      var total = n + q * 2;
      var svgNS = "http://www.w3.org/2000/svg";
      var svg = document.createElementNS(svgNS, "svg");
      svg.setAttribute("viewBox", "0 0 " + total + " " + total);
      svg.setAttribute("width", String(sizePx || 220));
      svg.setAttribute("height", String(sizePx || 220));
      var bg = document.createElementNS(svgNS, "rect");
      bg.setAttribute("width", String(total));
      bg.setAttribute("height", String(total));
      bg.setAttribute("fill", "#ffffff");
      svg.appendChild(bg);

      var d = "";
      for (var r = 0; r < n; r++) {
        for (var c = 0; c < n; c++) {
          if (mat[r][c]) {
            d += "M" + (c + q) + "," + (r + q) + "h1v1h-1z";
          }
        }
      }
      var path = document.createElementNS(svgNS, "path");
      path.setAttribute("d", d);
      path.setAttribute("fill", "#000000");
      svg.appendChild(path);
      return svg;
    }
  };
})(window);
