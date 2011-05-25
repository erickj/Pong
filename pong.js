/**
 * Pong: Not quite ping
 *
 * Unfortunately this implementation is severly limited by the remote host responding
 * to what is effectively port scans.  Further there is no real way to detect packet loss with
 * this implementation.  That being said, I think it's a fair attempt (or just amusing) way to
 * detect latency and jitter from the browser.
 *
 * Pong works by sending an xml http request to an _UNBOUND_ TCP socket on the remote host.
 * We rely on the remote host sending back an ICMP (dest host unreachable) or a TCP RST packet
 * to the local machine.

 * From RFC 792
 * @see http://tools.ietf.org/html/rfc792
 *

"If, in the destination host, the IP module cannot deliver the
datagram  because the indicated protocol module or process port is
not active, the destination host may send a destination
unreachable message to the source host."

 *
 * At the TCP layer this alerts the local machine that the TCP SYN has been rejected, then we use the
 * the AJAX state changes to record the timestamps.
 *
 * The method also works cross domain on browsers that support CORS due the preflight request that
 * we expect (need) to fail.
 *
 * From some basic testing I can get results within about 2ms of the corresponding wireshark observed time deltas.
 *
 * Here is a wireshark capture describing the network packets I'm talking about:
 *
No.     Time        Source                Destination           Protocol Info
  1     0.000000    10.0.1.7              65.98.96.234          TCP      62337 > 1000 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=3 TSV=665428761 TSER=0 SACK_PERM=1
  2     0.014332    65.98.96.234          10.0.1.7              ICMP     Destination unreachable (Host administratively prohibited)

 *
 * Naive attempts to use XHR as a ping tool end up with severely inaccurate results.  The problem is that
 * developers consider the HTTP Request/Response round trip equivalent to the ICMP ping echo/response
 * roundtrip.  It isn't.  Further if you actually hit a webserver then you add in the response processing
 * time to the request into the latency.  For example here is a capture of a simple HEAD request, the naive
 * approach actually measures from Packet 1 to Packet 7, but we really just want to measure Packet 1 to 2:
 *

No.     Time        Source                Destination           Protocol Info
  1     0.000000    192.168.0.165         65.98.96.234          TCP      63852 > 80 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=3 TSV=665500921 TSER=0 SACK_PERM=1
  2     0.028849    65.98.96.234          192.168.0.165         TCP      80 > 63852 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1460
  3     0.028914    192.168.0.165         65.98.96.234          TCP      63852 > 80 [ACK] Seq=1 Ack=1 Win=65535 Len=0
  4     0.029040    192.168.0.165         65.98.96.234          HTTP     HEAD / HTTP/1.1
  5     0.058051    65.98.96.234          192.168.0.165         TCP      80 > 63852 [ACK] Seq=1 Ack=167 Win=6432 Len=0
  6     0.419684    65.98.96.234          192.168.0.165         TCP      [TCP segment of a reassembled PDU]
  7     0.419687    65.98.96.234          192.168.0.165         HTTP     HTTP/1.1 200 OK
  8     0.419727    192.168.0.165         65.98.96.234          TCP      63852 > 80 [ACK] Seq=167 Ack=467 Win=65535 Len=0
  9     0.419744    192.168.0.165         65.98.96.234          TCP      63852 > 80 [ACK] Seq=167 Ack=468 Win=65535 Len=0
 10     0.419910    192.168.0.165         65.98.96.234          TCP      63852 > 80 [FIN, ACK] Seq=167 Ack=468 Win=65535 Len=0
 11     0.451457    65.98.96.234          192.168.0.165         TCP      80 > 63852 [ACK] Seq=468 Ack=168 Win=6432 Len=0

 *
 * NOTE: IMPORTANT
 * This script will not work if the remote host does not respond to requests to unbound ports. This
 * may be common as the recommendation only defines the requirement to send the ICMP packet as a "MAY"
 * see above.
 *
 * @example
 *

Pong.host = "www.quirksmode.org";
Pong.ping(function(res) { console.log(res.delta()); });
Pong.ping(function(res) { console.log(res.delta()); }, 10);

 *
 * @see http://www.w3.org/TR/XMLHttpRequest/
 * @see http://www.w3.org/TR/2007/WD-XMLHttpRequest-20070227/
 */
if (!window['XMLHttpRequestException']) { // chrome throws these but ff 4 doesn't define it
  XMLHttpRequestException = {};
}

var Pong = function() {};

Pong.prototype = {
  host: null,
  port: 65000,
  method: "HEAD",
  async: false,

  interval: 1000,
  timeout: 5000,
  tid: null,
  aborted: null,

  cb: null,

  stateTimers: null,

  /**
   * @param count - just like the ping -c flag
   * @param doContextCorrection - a hack to make the result more accurate...
   *   it will run an extra ping and trash the first data. since we're dealing
   *   with millisecond accuracies this will help remove any latency from
   *   context switching the current js environment back into memory.
   *   default value: true
   */
  ping: function(cb, count, doContextCorrectionHack, host, port) {
    var that = this;

    this.stateTimers = [];
    this.aborted = null;

    host = host || this.host;
    port = port || this.port;

    this.cb = cb || this.cb; // set for callback in readyState handler
    cb = this.cb;            // store for next if/elif block

    if (doContextCorrectionHack === undefined)
      doContextCorrectionHack = true;

    if (doContextCorrectionHack) {
      var tmp = this.timeout;
      this.cb = function() {
        that.timeout = tmp;
        that.ping(cb, count, false, host, port);
      };
      this.timeout = null;
    // TODO: the repeat parameter will screw w/ a scope of cb that isn't the global object
    } else if (count && count > 1) {
      this.cb = function() {
        cb.apply(that,arguments); // this is going to fuck up the scope of cb
        setTimeout(function() {
          that.ping(cb, --count, doContextCorrectionHack, host, port);
        },that.interval);
      };
    }

    var io = this.io();
    io.open(this.method, this.dst(host, port), this.async);

    try {
      if (this.timeout) {
        this.tid = window.setTimeout(function() {
          console.warn('Timeout fired');
          that.abort("timeout");
        },this.timeout);
      }

      io.send();
    } catch(e) {
      console.warn(e);
      if (e.constructor != XMLHttpRequestException) throw e;
    }
  },

  abort: function(reason) {
    console.error("Aborted due to: ", reason);
    this.aborted = true;
    this.io().abort();
    this.fireCallback();
  },

  fireCallback: function() {
    if (this.cb && this.cb.call) {
      this.cb.call(this, this.result());
    }
  },

  result: function() {
     var ret = {
       aborted: this.aborted,
       start: this.stateTimers[1],
       end: this.stateTimers[2] || this.stateTimers[4],
       delta: function() {
         if (this.aborted) return "request timed out";

         var start = this.start,
           end = this.end;

         // mozilla for some reason has microsecond accuracy on their events
         // let's get rid of that
         var dummy = Date.now().toString();
         start = start.toString().slice(0,dummy.length);
         end = end.toString().slice(0,dummy.length);

         return parseInt(end) - parseInt(start);
       }
     };
     return ret;
  },

  /* private */
  // return XHR
  io: function() {
    if (!this._io) {
      this._io = new XMLHttpRequest();
      this.bindXHRHandlers(this._io);
    }
    return this._io;
  },

  /* private */
  dst: function(host,port) {
    return "http://" + host.toString() + ":" + port.toString() + "/";
  },

  /* private */
  /**
   * callback handlers
   */
  handlerReadyStateChange: function(evt) {
    console.log(Date.now(), "ready state changed", evt.target.readyState);
    this.stateTimers[evt.target.readyState] = evt.timeStamp;

    if (evt.target.readyState != 1 && this.tid) {
      window.clearTimeout(this.tid);
      this.tid = null;
    }

    if (evt.target.readyState == 4 && this.cb) {
      if (evt.target.status) {
        var msg = "Invalid Ping result status: " + new String(evt.target.status);
        throw new Error(msg);
      }

      this.fireCallback();
    }
  },

  /* private */
  handlerError: function(evt) {
//    if (console && console.error) console.error("handler error:", evt);
    evt.cancelBubble = true;
    evt.stopPropagation();
  },

  /* private */
  /**
   * effectively static
   */
  bindXHRHandlers: function(xhr, target) {
    target = target || this;

    xhr.onreadystatechange = function() {
      target.handlerReadyStateChange.apply(target, arguments);
    };

    xhr.onerror = function() {
      target.handlerError.apply(target, arguments);
    };
  }
};
