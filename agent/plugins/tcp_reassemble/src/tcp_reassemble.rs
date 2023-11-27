/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use log::{error, warn};
use public::ringbuffer::{RingBuf, RingBufSlice};
use std::mem::swap;

pub const DIRECTION_0: u8 = 0;
pub const DIRECTION_1: u8 = 1;

const ENABLE_LOG: bool = true;

macro_rules! tcp_reassemble_log {
    ($self: expr, $fmt: literal, $($args: expr),* $(,)?) => {
        if ENABLE_LOG{
            warn!("tcp reassemble info: flow_id: {}, direction: {:?}. {}", $self.flow_id, $self.direction, format!($fmt,$($args),*))
        }
    };
}

#[derive(Debug)]
pub enum TcpReassembleError {
    // the frame seq is before the base seq
    FrameBeforeBase,
    // buffer 为空并且 payload 长度超过 buffer 最大值
    PayloadExceedMaxBufferSize,
    // frame exist
    FrameExist,
    // tcp seq and payload not correspond or buffer not enough to place the frame
    BufferFlush(Vec<(Vec<u8>, Vec<TcpFragementMeta>)>),
}

enum FramePositionResult {
    BeforeBase,
    Before(usize), // the frame is before idx
    After(usize),  // the frame is after idx
    Buffered,      // the frame is buffered, should ignore
    BadFrame(String),
}

pub type TcpReassembleResult = Result<(), TcpReassembleError>;

// tcp 序列号存在换回的情况,目前认为只要差值不超过 2G 都认为没有环回
fn is_seq_loopback(s1: u32, s2: u32) -> bool {
    const HALF_TCP_SEQ_RANGE: u32 = 2147483648;
    s1.abs_diff(s2) > HALF_TCP_SEQ_RANGE
}

fn is_seq_before(before: u32, after: u32) -> bool {
    let lb = is_seq_loopback(before, after);
    (before < after && !lb) || (before > after && lb)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFragementMeta {
    pub(super) seq: u32,
    pub payload_len: usize,
    /*
        由于重组可能出现各种情况,需要记录一下解析到哪一帧.目前的重组策略是当第一段连续的数据有变化,例如(f 指 frame)
        case 1:
        | f1 |
        insert f2
        | f1 | f2 |
        insert f3
        | f1 | f2 | f3 |

        这种情况,第一次f1经过解析,判断为需要重组,f1必定是 req/resp 的开始,所以 is_parsed 标记为true
        插入 f2,这时候连续数据出现变化,f1 + f2 的 payload 合并进行解析,发现还需要重组,这时候 f2.is_parsed 标记为true
        ...

        case 2:
        | f1 |
        insert f3
        | f1 | 保留空间 | f3 |
        insert f2
        | f1 | f2 | f3 |

        这种情况,第一次f1经过解析,判断为需要重组,f1必定是 req/resp 的开始,所以 is_parsed 标记为true
        插入 f3 ,由于连续的数据没有变化,不触发解析
        插入f2,连续的数据出现变化,这时候,由于f1已经被标记为已解析,所以这时候将f1+f2 拼接并解析,

            case 2.1 解析成功或失败,pop f1 和 f2, f3 单独丢解析
                case 2.1.1 失败,直接丢弃
                case 2.1.2 需要重组,f3.is_parsed 标记为true
                case 2.1.3 成功, pop f3

            case 2.2 判断为需要重组,f2.is_parsed 标记为true, 并且f1+f2+f3 拼接并解析
                case 2.2.1 失败或成功, pop f1 f2 f3
                case 2.2.2 判断需要重组,f3.is_parsed 标记为true,并等待后续数据
                    假如这时候 insert f4:
                        由于f1f2f3已经标记为已解析,当f4插入是,直接拼接 f1+f2+f3+f4 并解析,这时候情况类似 case 2.1
                    加入这时候 insert f5, 由于连续数据没有辩护,情况类似 case 2
    */
    pub is_parsed: bool,
    // cap seq and timestamp 仅用于流结束 flush 的时候用于构建 ParseParam, 重组逻辑不会用到
    pub cap_seq: u64,
    pub timestamp: u64, // micro sec
}

impl TcpFragementMeta {
    // whether the next frame is consequent
    fn is_next_consequent(&self, next: &Self) -> bool {
        self.next_seq() == next.seq
    }

    fn next_seq(&self) -> u32 {
        self.seq + (self.payload_len as u32)
    }
}

pub struct BufferData {
    // use for log
    pub(super) flow_id: u64,
    // use for log
    pub(super) direction: u8,
    // buffer with packet_size length, prealloc, len = l7_log_packet_size
    pub(super) buf: RingBuf<u8>,
    // len = max_tcp_reassemble_frag
    pub(super) tcp_meta: Vec<TcpFragementMeta>,
    pub(super) base_seq: Option<u32>,
    pub(super) max_frame: usize,
}

impl BufferData {
    fn tcp_frame_fmt(&self) -> String {
        let mut s = String::new();
        if self.tcp_meta.is_empty() {
            s = format!("| base seq:{} |", self.base_seq.unwrap_or(0));
            return s;
        }
        let first = self.tcp_meta.first().unwrap();
        if first.seq == self.base_seq.unwrap() {
            s.push_str(format!("| f1, seq:{} ", first.seq).as_str());
        } else {
            s.push_str(
                format!(
                    "| prev: {}| f1, seq:{} ",
                    first.seq - self.base_seq.unwrap(),
                    first.seq
                )
                .as_str(),
            );
        }
        let mut prev = first.clone();
        for (i, t) in self.tcp_meta.iter().skip(1).enumerate() {
            if prev.is_next_consequent(t) {
                s.push_str(format!("| f{}, seq:{} ", i + 2, t.seq).as_str());
            } else {
                s.push_str(
                    format!("| prev: {} | f{}, seq:{} ", t.seq - prev.seq, i + 2, t.seq).as_str(),
                );
            }
            prev = t.clone();
        }
        s.push('|');
        s
    }

    fn frame_offset(&self, t: &TcpFragementMeta) -> usize {
        (t.seq - self.base_seq.unwrap()) as usize
    }

    fn is_empty(&self) -> bool {
        self.tcp_meta.is_empty()
    }

    fn buf_size(&self) -> usize {
        self.buf.cap()
    }

    // whether the frame is before base
    fn before_base(&self, f: &TcpFragementMeta) -> bool {
        self.base_seq
            .map(|base_seq| is_seq_before(f.seq, base_seq))
            .unwrap_or(false)
    }

    // 获取第一段连续数据帧数量,这里无视在第一帧之前的预留buffer
    pub(super) fn get_consequent_idx(&self) -> Option<usize> {
        let mut f = None;
        if self.tcp_meta.is_empty() {
            None
        } else if self.tcp_meta.len() == 1 {
            Some(0)
        } else {
            self.tcp_meta
                .iter()
                .zip(self.tcp_meta.iter().skip(1))
                .position(|(a, b)| {
                    if a.is_next_consequent(b) {
                        false
                    } else {
                        f = Some(a);
                        true
                    }
                })
                .and_then(|i| Some(i))
                .or(Some(self.tcp_meta.len() - 1))
        }
    }

    // pop first n frame
    // must assure invoke tcp_reassemble() at lease once that base_seq is not None
    // return (payload, tcp_meta)
    fn pop_frame_n(&mut self, n: usize) -> (Vec<u8>, Vec<TcpFragementMeta>) {
        if n == 0 || n > self.tcp_meta.len() {
            panic!("drain tcp frame is 0 or tcp frame out of index");
        }

        let mut p = self.tcp_meta.split_off(n);
        swap(&mut p, &mut self.tcp_meta);

        let latest = p.last().unwrap();
        let start = self.frame_offset(p.first().unwrap());
        let off = self.frame_offset(latest) + latest.payload_len - start;

        self.base_seq = self.base_seq.map(|seq| seq + off as u32 + start as u32);
        self.buf.pop_n(start);
        let payload = self.buf.pop_n(off);
        tcp_reassemble_log!(
            self,
            "pop frame {}, current buffer data: {}\n",
            n,
            self.tcp_frame_fmt()
        );
        (payload, p.to_vec())
    }

    fn drain_frame_n(&mut self, n: usize) -> usize {
        if n == 0 || n > self.tcp_meta.len() {
            panic!("drain tcp frame is 0 or tcp frame out of index");
        }
        self.tcp_meta = self.tcp_meta.split_off(n - 1);
        let f = self.tcp_meta.remove(0);
        let off = self.frame_offset(&f) + f.payload_len;
        self.base_seq = self.base_seq.map(|s| s + off as u32);

        self.buf.drain_n(off);
        tcp_reassemble_log!(
            self,
            "frain frame {}, current buffer data: {}\n",
            n,
            self.tcp_frame_fmt()
        );
        off
    }

    pub(super) fn pop_consequent_seq_data(&mut self) -> (Vec<u8>, Vec<TcpFragementMeta>) {
        let Some(meta_idx) = self.get_consequent_idx() else {
            return (vec![], vec![]);
        };
        self.pop_frame_n(meta_idx + 1)
    }

    pub(super) fn get_consequent_buffer(
        &mut self,
    ) -> Option<(&mut [TcpFragementMeta], RingBufSlice<u8>)> {
        let idx = self.get_consequent_idx()?;
        let frist = self.tcp_meta.get(0).unwrap();
        let latest = self.tcp_meta.get(idx).unwrap();
        let start = self.frame_offset(frist);
        let off = self.frame_offset(latest) + latest.payload_len - start;

        Some((
            &mut self.tcp_meta.as_mut_slice()[..idx + 1],
            self.buf.to_range_vec(start..off),
        ))
    }

    // 获取 base_seq 与第一帧之间的预留空间大小
    pub(super) fn get_waitting_buf_len_before_first_frame(&self) -> Option<usize> {
        if self.tcp_meta.len() == 0 {
            None
        } else {
            Some(self.frame_offset(self.tcp_meta.get(0).unwrap()))
        }
    }

    // 清空 base_seq 与第一帧之间的预留空间大小
    pub(super) fn drain_waitting_buf_len_before_first_frame(&mut self) -> usize {
        if self.tcp_meta.len() == 0 {
            return 0;
        }
        let f = self.tcp_meta.get(0).unwrap();
        let b = self.frame_offset(f);
        self.buf.drain_n(b);
        self.base_seq = Some(f.seq);
        tcp_reassemble_log!(
            self,
            "drain_waitting_buf_len_before_first_frame, current buffer data: {}\n",
            self.tcp_frame_fmt()
        );
        b
    }

    // must assure the base seq is correct and frame is insert in correct pos and payload + preserve can not exceed
    fn insert_frame(&mut self, pos: usize, f: TcpFragementMeta, payload: &[u8]) {
        self.tcp_meta.insert(pos, f);
        let off = self.frame_offset(&f);
        if off > self.buf.len() {
            // perserve the buffer
            self.buf.perserve_n(off - self.buf.len());
        }
        self.buf.extend_from_offset(off, payload.iter().map(|b| *b))
    }

    pub(super) fn flush_all_buf(&mut self) -> Vec<(Vec<u8>, Vec<TcpFragementMeta>)> {
        let mut v = vec![];
        loop {
            let (payload, meta) = self.pop_consequent_seq_data();
            let len = payload.len();
            if len == 0 {
                break;
            }
            v.push((payload, meta));
        }
        tcp_reassemble_log!(
            self,
            "flush all buffer, current buffer data: {}\n",
            self.tcp_frame_fmt()
        );
        v
    }

    fn get_frame_position(&self, f: &TcpFragementMeta) -> FramePositionResult {
        assert_eq!(self.is_empty(), false);

        if self.before_base(f) {
            return FramePositionResult::BeforeBase;
        }

        let latest = self.tcp_meta.last().unwrap();
        // if frame after the latest
        if latest.is_next_consequent(f) {
            return FramePositionResult::After(self.tcp_meta.len() - 1);
        }
        if is_seq_before(latest.seq, f.seq) {
            if is_seq_before(latest.next_seq(), f.seq) {
                return FramePositionResult::After(self.tcp_meta.len() - 1);
            } else {
                return FramePositionResult::BadFrame(format!("the frame with seq: {}, payload_len: {}  after frame with seq:{}, payload_len: {} not conform tcp protocol",f.seq,f.payload_len,latest.seq,latest.payload_len));
            }
        }

        let (base_seq, latest_seq) = (self.base_seq.unwrap(), self.tcp_meta.last().unwrap().seq);
        // if the tcp seq is all increase, can use binary search
        let idx = if latest_seq >= base_seq {
            let (mut start, mut end) = (0, self.tcp_meta.len() - 1);
            while end > start {
                let mid = (end + start) / 2;
                if f.seq > self.tcp_meta.get(mid).unwrap().seq {
                    start = mid + 1
                } else {
                    end = mid
                }
            }
            end
        } else {
            let mut previous_seq = base_seq;
            let mut idx = None;
            for (i, t) in self.tcp_meta.iter().enumerate() {
                /*
                    use the difference value can regardless whether loopback
                    previous seq                                   t seq
                        |----------------(f seq?)-------------------|--------------(f seq?)---------|
                */
                if t.seq == f.seq {
                    return FramePositionResult::Buffered;
                }
                if (t.seq - previous_seq) > (f.seq - previous_seq) {
                    // frame is between previous and t
                    idx = Some(i);
                    break;
                }
                previous_seq = t.seq;
            }

            // the frame seq is between base and latest
            idx.unwrap()
        };

        let next = self.tcp_meta.get(idx).unwrap();
        if next.seq == f.seq {
            // for simpify, ignore the payload length
            return FramePositionResult::Buffered;
        }

        let previous = if idx == 0 {
            // 如果 idx 是 0,说明这一帧在 base_seq 和第一帧之间,只要当前帧>=base_seq,并且当前帧的下一帧的序列号<=第一帧,就认为是合法的帧
            TcpFragementMeta {
                seq: base_seq,
                payload_len: 0,
                is_parsed: false,
                timestamp: 0,
                cap_seq: 0,
            }
        } else {
            *self.tcp_meta.get(idx - 1).unwrap()
        };

        // 当前帧 在 上一帧的下一帧之后,并且下一帧 在 当前帧的下一帧之后,就认为是合法的帧
        // | previous | f | next |
        // 这里需要符合的条件是 f 的序列号要在 previous 的下一帧序列号之后, 并且 f 的下一帧的序列号要在 next 之前
        if previous.is_next_consequent(f)
            || f.is_next_consequent(next)
            || (is_seq_before(previous.next_seq(), f.seq) && is_seq_before(f.next_seq(), next.seq))
        {
            return FramePositionResult::Before(idx);
        }
        FramePositionResult::BadFrame(format!("the frame with seq: {}, payload_len: {}  between frame with seq:{}, payload_len: {}  and frame with seq:{}, payload_len: {} not conform tcp protocol",
             f.seq,f.payload_len,
             previous.seq,
             previous.payload_len,
             next.seq,
             next.payload_len))
    }

    /*
        tcp 重组的设计

        tcp 重组维持一个固定长度的 ringbuffer 和一个定长 TcpFragementMeta 的数组, 由于 tcp 存在丢包,重传,乱序等情况,所以需要记录一个 bseq seq ,并且需要预留空间.
        因此, tcp buffer 的并不一定是连续的数据,buffer 里可能是断断续续的数据,即 buffer 里 tcp 序列号并不连续(连续指的是 tcp seq + payload_len = next frame tcp seq,
        这里有序列号环回的情况).因此对于协议解析来说,必须要首段连续tcp数据发生变化,并且 base_seq 等于第一帧的 tcp seq,才会出发解析,例如:
        | f1 | f2 | 这里 base seq 是 f1 的seq

        这时候如果 f3 是 f2 的下一帧(f2.seq + f2.payload_len = f3.seq),则会触发解析逻辑,但是
        | f1 | f2 | 预留空间 | f3 |, 这种情况是不会触发解析,会等待 f2 和 f3 中间的数据填满.

        每一次解析过后,都会记录一个当前解析的位置,例如上面的例子:
        | f1 | 这时候写入 f2, 会触发解析逻辑,如果这时候判断还需要重组,f2 会标记为 is_parsed,表示 f1 + f2 已经解析过

        这时候写入 f3
        | f1 | f2 | f3 | ,这时候触发解析,由于 f1 + f2 已经解析过,所以直接从 f1 + f2 + f3 开始解析

        由于 buffer 是固定大小, 所以存在某些情况需要强制刷新 buffer,例如收到不符合 tcp 协议的包,收到数据超出缓冲区大小 等等,数据的读取和刷新有两种方法:
            1. 正常接收到连续的帧,触发解析逻辑,这时候会返回 ringbuffer 对应的字节数组和 TcpFragementMeta 对应的 slice,buffer 数据并不会有变化.
            2. buffer 数据刷新:
                buffer 刷新必定是以连续的数据作为单位,例如 | f1 | f2 | perserve | f3 | f4 | perserve | 刷新会返回2组数据, f1+f2, f3+f4 刷新数据可能会部分刷新也可能全部刷新,例如:

                2.1: 收到数据超出缓冲区大小, 例如 | perserve1 | f1 | f2 | perserve2 | f3 | f4 | perserve2 | f5 |, 这时候收到f6,与f5连续,但超过 buffer 大小,这时候会
                    2.1.1 直接丢弃 perserve1
                    2.1.2 如果还是不够, 刷新缓冲区,pop 第一段连续数据, 这里就是 f1 + f2
                    2.1.3 还是不够,直接丢弃 perserve2,还是不够,pop f3 + f4
                    ...
                2.2, 收到不符合 tcp 协议的数据
                    直接刷新整个缓冲区,这里就是返回 [f1+f2, f3+f4, f5]

        具体实现逻辑如下:

        ringbuffer 固定一个长度,例如 1024, 当第一个包过来的时候,会记录当前包为 base seq, TcpFragementMeta 会 push 当前帧,后续的包会有如下几种情况:

            case -1: seq not conform the tcp protocol(for example payload length and tcp seq not correspond):
                flush all the frame and drop current frame.

            case 0: new frame or buffer empty:
                case 0.1: paylaod size >= buffer size, set the base_seq = paylaod size + seq ,not cache the frame
                case 0.2: paylaod size < buffer, set the base_seq = seq, cache the frame

            case 1: frame before the base_seq, regardless the payload size:
                return error directly

            case 2: frame can place to buffer:
                place to buffer
                case 2.1: if tcp frame is exceed (after place current frame):
                    pop the first consequent data

            case 3: not enough buffer to place the frmae
                according to tcp protocol, if not enough buffer to place the frmae, this frame must after the latest frame in the buffer (because
                in tcp prorocol, the difference value of tcp seq is the tcp stream size between two frame). more exaclly, the frame seq must conform
                that: seq >= latest frame seq + latest frame payload length (in non lookback case)
                first, try to drain the waitting buffer before first frame:
                    | preserve buffer| first frame | ... | latest frame | ...(not enough buffer to place frmae) |
                    after drain the buffer:
                    | first frame | ... | latest frame | free space |
                    if the free space still not enough to place the frame, drop the consequent data and drain the waitting buffer before first frame
                    until have enough buffer to place the frame
                    | consequent data 1| preserve buffer | consequent data 2| ... | latest frame | free space |
                    | preserve buffer | consequent data 2| ... | latest frame |          free space           |
                    | consequent data 2| ... | latest frame |                   free space                    |
                    ...
                if all frame pop and current payload < buffer size:
                    is same to case 0.2
                if all frame pop and payload >= buffer size
                    case 3.1: the frame is the next frame of latest frame:
                        // TODO 这里有实现上的选择问题
                           假如 buffer 长度 1024 重组前 buffer 是 | preserve 23 | f1, len 1000 |
                           这时候来了一帧 f2 长度 1024,和 f1 连续, 这时候有两个选择,
                           3.1.1 将 f2 的 前 24 字节拼接到 f1, 达到1024,但是如果 f2 是新请求的话就丢失请求
                           3.1.2 f2 作为单独一帧处理,相当于 case 3.2, 但是如果 f2 是 f1 是同一个请求那么 f1 的数据将不完整.
                           目前出于与不重组更接近的原则,使用3.1.1.2

                    case 3.2: not the next frame of latest frame:
                        pop the current frame Individually

        解析逻辑:
            按照实现逻辑分情况讨论:
                case 0: 返回 Payload::Metapacket 是否可重组取决于 payload 是否超过 bffer, 超过buffer长度则不可重组, parse 只解析1次
                    1. 如果解析成功, 直接返回结果
                    2. 失败:
                        1. 返回 非 NeedMoreData 错误, 直接往上传递错误
                        1. 返回 NeedMoreData 并且 payload 长度 <  bffer 长度, 丢进去重组, 并且更新 base seq
                        2. 返回 NeedMoreData 并且 payload 长度 >= bffer 长度, 仅仅更新 base seq

                case 2: 如果这时候第一段连续数据出现变化,即第一帧与 base seq 之间没有 perserve 并且连续数据出现变化,例如:
                    | f1 | f2 | 这时候加入f3 ,f3 与 f2 连续,连续数据由 f1 + f2 变成 f1 + f2 + f3
                    | f1 | perserve | f3 | 这时候加入f2 ,连续数据由 f1 变成 f1 + f2 + f3

                    1. 假如加入新帧后 tcp frame 没有 exceed, 那么这时候 payload 返回 Pyaload::InFlightBuffer, 这时候的 tcp frame 是 buffer 的引用, parse 可能解析多次.
                        假设 buffer 现在是(frame, is_parsed): | f1, true| f2, false | f3, false | 第一帧由于已经解析过所以是 true (buffer的第一帧不一定是true, 参考 具体实现逻辑 case 3)

                        这时候 frame start = 0, frame off = 1(因为 f1 已解析过, 如果 f1 未解析过则是0), 尝试 f1 + f2 (即 frame[start,start+off])解析, can_reassemble = true, 因为还有f3可以补上,
                            1. 成功, 将会暂时在 payload 中记录 frame start = 2, frame off = 0, 继续将 f3(这时候 payload::get() 返回frame[2,2+0], 即 f3) 进行解析 ,can_reassemble = false, 因为后面没有帧可以补
                                a. 成功, 则 frame start = 3, frame off = 0, 结束解析
                                b. 失败
                                    1. 返回 NeedMoreData, no ops, 因为 f3 本来已经经过重组.
                                    2. 返回其他错误, payload 中记录 frame start = 3, frame off = 0
                                    结束解析

                            2. 失败
                                a. 返回 NeedMoreData, payload 中记录 frame start = 0, frame off = 2, 这时候, 尝试 f1 + f2 + f3 进行解析(frame[0,2]) can_reassemble = true, 虽然后面没有帧可以补, 但由于这是在 buffer 里的连续数据, 后续可能还有数据
                                    1. 成功, payload 中记录 frame start = 3, frame off = 0,
                                    2. 失败
                                        a. 返回 NeedMoreData, no ops, 因为 f3 本来已经经过重组.
                                        b. 返回其他错误, payload 中记录 frame start = 3, frame off = 0

                                结束解析

                        这时候 除了 buffer 会丢弃 $(frame start) 帧, frame start 表示已经解析过并且不能重组的帧


                case 2 tcp frame exceed, flush了连续的数据 或 case 3 flush 了数据, 例如
                    case 2 tcp frame exceed(max frame 5):
                    | f1 | f2 | f3 | perserve | f4 | f5 |, 这时候加入 f6, 由于超过了最大限制, 这时候 flush f1 + f2 + f3, buffer剩余 | perserve | f3 | f4 | f5 |

                    这时候 | f1 | f2 | f3 | 已经不在 buffer, payload 返回 Pyaload::FlushedBuffer, 情况和上面类似,除了 1.2.a 里 can_reassemble = false, 因为后面没有帧可以补(因为不在 buffer)

    */
    pub(super) fn reassemble(
        &mut self,
        seq: u32,
        payload: &[u8], // payload must not prune in the param
        timestamp: u64,
        cap_seq: u64,
    ) -> TcpReassembleResult {
        tcp_reassemble_log!(
            self,
            "enter reassemble, seq: {}, payload_len: {}, current buffer data:\n {}",
            seq,
            payload.len(),
            self.tcp_frame_fmt()
        );

        let mut frame = TcpFragementMeta {
            seq,
            payload_len: payload.len(),
            is_parsed: false,
            timestamp,
            cap_seq,
        };

        // frame before than base frame, ignore. (case 1)
        if self.before_base(&frame) {
            tcp_reassemble_log!(self, "return due to before base",);
            return Err(TcpReassembleError::FrameBeforeBase);
        }

        // case 0: buf empty, is the first frame in this direction, set the frame as first frame
        if self.is_empty() {
            // buffer 由 l7 log size 控制,这里理论上不可能大于,只可能等于
            if payload.len() >= self.buf_size() {
                // case 0.1
                // it not return the frame because buf empty indicate the frame had parsed
                self.base_seq = Some(frame.next_seq());

                tcp_reassemble_log!(self, "return due to payload len larger than buffer len",);
                return Err(TcpReassembleError::PayloadExceedMaxBufferSize);
            } else {
                // case 0.2
                self.base_seq = Some(frame.seq);
                // buffer 为空, 说明这一帧已经解析过
                frame.is_parsed = true;
                self.insert_frame(0, frame, payload);

                tcp_reassemble_log!(
                    self,
                    "insert the frame, current buffer data:\n {}",
                    self.tcp_frame_fmt(),
                );
                return Ok(());
            }
        }

        match self.get_frame_position(&frame) {
            // before idx imply the buffer have enough space to place the frame
            FramePositionResult::Before(idx) => {
                // case 2
                self.insert_frame(idx, frame, payload);
                tcp_reassemble_log!(
                    self,
                    "insert the frame, current buffer data:\n {}",
                    self.tcp_frame_fmt(),
                );
                if self.tcp_meta.len() > self.max_frame {
                    // case 2.1
                    let pop_data = self.pop_consequent_seq_data();
                    tcp_reassemble_log!(
                        self,
                        "return due to tcp frame exceed, pop consequent seq data, current buffer data:\n {}",
                        self.tcp_frame_fmt()
                    );
                    return Err(TcpReassembleError::BufferFlush(vec![pop_data]));
                }
                tcp_reassemble_log!(self, "return ok",);
                Ok(())
            }
            FramePositionResult::After(idx) => {
                // if not after the latest, imply the buffer have enough space to place the frame
                // if after latest, maybe not enough buffer space to place the frmae
                // 目前的逻辑这里必定是 latest
                if idx != self.tcp_meta.len() - 1
                    || self.frame_offset(&frame) + frame.payload_len <= self.buf_size()
                {
                    // case 2
                    self.insert_frame(idx + 1, frame, payload);
                    tcp_reassemble_log!(
                        self,
                        "insert the frame, current buffer data:\n {}",
                        self.tcp_frame_fmt(),
                    );
                    if self.tcp_meta.len() > self.max_frame {
                        // case 2.1
                        let pop_data = self.pop_consequent_seq_data();
                        tcp_reassemble_log!(
                            self,
                            "return due to tcp frame exceed, pop consequent seq data, current buffer data:\n {}",
                            self.tcp_frame_fmt()
                        );
                        return Err(TcpReassembleError::BufferFlush(vec![pop_data]));
                    }
                    tcp_reassemble_log!(self, "return ok",);
                    return Ok(());
                }

                // not enough buffer space to place the frame
                // case 3
                let is_latest_next = self.tcp_meta.last().unwrap().is_next_consequent(&frame);
                let mut p = vec![];
                while self.frame_offset(&frame) + frame.payload_len > self.buf_size()
                    && !self.tcp_meta.is_empty()
                {
                    if self.get_waitting_buf_len_before_first_frame().unwrap() != 0 {
                        self.drain_waitting_buf_len_before_first_frame();
                        tcp_reassemble_log!(self, "drain waitting buf before first due to not enough buffer, current buffer data:\n {}", self.tcp_frame_fmt());
                        continue;
                    }

                    // base seq 与第一帧没有预留空间,只能pop出第一段连续的帧
                    p.push(self.pop_consequent_seq_data());
                    tcp_reassemble_log!(self, "pop consequent seq data due to not enough buffer, current buffer data:\n {}", self.tcp_frame_fmt());
                }

                if self.is_empty() && payload.len() < self.buf_size() {
                    //  same as case 0.2
                    self.base_seq = Some(frame.seq);
                    self.insert_frame(0, frame, payload);
                    tcp_reassemble_log!(
                        self,
                        "insert the frame, return flush, current buffer data:\n {}",
                        self.tcp_frame_fmt(),
                    );
                    return Err(TcpReassembleError::BufferFlush(p));
                }

                if self.frame_offset(&frame) + frame.payload_len < self.buf_size() {
                    self.insert_frame(self.tcp_meta.len(), frame, payload);
                    tcp_reassemble_log!(
                        self,
                        "insert the frame, return flush, current buffer data:\n {}",
                        self.tcp_frame_fmt(),
                    );
                    return Err(TcpReassembleError::BufferFlush(p));
                }

                // all buffer pop, but still can not place the frame
                tcp_reassemble_log!(
                    self,
                    "all buffer pop, also not enough buffer, current buffer data:\n {}",
                    self.tcp_frame_fmt(),
                );
                if is_latest_next {
                    // case 3.1

                    // case 3.1.1
                    // let latest = p.last_mut().unwrap();
                    // let latest_payload = &mut latest.0;
                    // let latest_frames = &mut latest.1;
                    // latest_payload.extend(&payload[..(self.buf_size() - latest_payload.len())]);
                    // latest_frames.push(frame);

                    // case 3.1.2, same as 3.2
                    p.push(((&payload[..self.buf_size()]).to_vec(), vec![frame]));
                    tcp_reassemble_log!(self, "is next frame of latest",);
                } else {
                    // case 3.2
                    p.push(((&payload[..self.buf_size()]).to_vec(), vec![frame]));
                    tcp_reassemble_log!(self, "not the next frame of latest",);
                }
                let _ = self.base_seq.insert(frame.seq + frame.payload_len as u32);
                tcp_reassemble_log!(
                    self,
                    "return flush due to not enough buffer, current buffer data:\n {}",
                    self.tcp_frame_fmt()
                );
                Err(TcpReassembleError::BufferFlush(p))
            }
            FramePositionResult::Buffered => {
                tcp_reassemble_log!(self, "return frame exist",);
                Err(TcpReassembleError::FrameExist)
            }
            FramePositionResult::BadFrame(s) => {
                error!("{}", s);
                let mut flush_data = self.flush_all_buf();
                flush_data.push((payload.to_vec(), vec![frame]));
                tcp_reassemble_log!(
                    self,
                    "return flush due to bad frame, current buffer data:\n {}",
                    self.tcp_frame_fmt()
                );
                Err(TcpReassembleError::BufferFlush(flush_data))
            }
            _ => unreachable!(),
        }
    }
}

pub struct TcpFlowReassembleBuf {
    buf_0: BufferData,
    // for serial protocol, only need single buffer, buf_1 and meta_1 will clean and keep empty after check_payload() success
    buf_1: BufferData,

    current_direction: Option<u8>,

    is_serial_protocol: bool,
}

impl TcpFlowReassembleBuf {
    pub fn new(buf_size: usize, max_frame: usize, flow_id: u64) -> Self {
        Self {
            buf_0: BufferData {
                flow_id: flow_id,
                direction: DIRECTION_0,
                buf: RingBuf::new(buf_size),
                tcp_meta: Vec::with_capacity(max_frame),
                base_seq: None,
                max_frame,
            },
            buf_1: BufferData {
                flow_id: flow_id,
                direction: DIRECTION_1,
                buf: RingBuf::new(buf_size),
                tcp_meta: Vec::with_capacity(max_frame),
                base_seq: None,
                max_frame,
            },
            current_direction: None,
            is_serial_protocol: false,
        }
    }

    /*
        some serial protocol not need the two side buffer when data from af_packet.
        the follow protocol will set to serial proto:
            HTTP1
            Redis
        due to ebpf will disorder, it must use two side buffer in any protocol.
    */
    pub fn set_to_serial_proto(&mut self) {
        if self.is_serial_protocol {
            return;
        }
        self.is_serial_protocol = true;
        self.buf_1 = BufferData {
            flow_id: 0,
            direction: 0,
            buf: RingBuf::new(1),
            tcp_meta: vec![],
            base_seq: None,
            max_frame: 0,
        };
    }

    pub fn buf_is_empty(&self, direction: u8) -> bool {
        match direction {
            DIRECTION_0 => self.buf_0.is_empty(),
            DIRECTION_1 => self.buf_1.is_empty(),
            _ => unreachable!(),
        }
    }

    pub fn reassemble_non_serial(
        &mut self,
        seq: u32,
        payload: &[u8], // payload must not prune in the param
        direction: u8,
        timestamp: u64,
        cap_seq: u64,
    ) -> TcpReassembleResult {
        assert!(!self.is_serial_protocol);
        match direction {
            DIRECTION_0 => self.buf_0.reassemble(seq, payload, timestamp, cap_seq),
            DIRECTION_1 => self.buf_1.reassemble(seq, payload, timestamp, cap_seq),
            _ => unreachable!(),
        }
    }

    pub fn reassemble_serial(
        &mut self,
        seq: u32,
        payload: &[u8], // payload must not prune in the param
        direction: u8,
        timestamp: u64,
        cap_seq: u64,
    ) -> TcpReassembleResult {
        assert!(self.is_serial_protocol);

        let buf = &mut self.buf_0;

        if self.current_direction.is_none() {
            let r = buf.reassemble(seq, payload, timestamp, cap_seq);
            if !buf.is_empty() {
                self.current_direction = Some(direction);
            }
            r
        } else {
            let r = if self.current_direction.unwrap() == direction {
                let r = buf.reassemble(seq, payload, timestamp, cap_seq);
                if !buf.is_empty() {
                    self.current_direction = Some(direction);
                }
                r
            } else {
                let f = buf.flush_all_buf();
                let mut r = buf.reassemble(seq, payload, timestamp, cap_seq);
                if !buf.is_empty() {
                    self.current_direction = Some(direction);
                }

                let _ = r.as_mut().map_err(|e| match e {
                    TcpReassembleError::BufferFlush(d) => {
                        d.extend(f);
                    }
                    _ => {}
                });
                r
            };
            r
        }
    }

    // 这里基本来判断第一帧的序列号是否等于 base_seq
    pub fn get_waitting_buf_len_before_first_frame(&self, direction: u8) -> Option<usize> {
        match direction {
            DIRECTION_0 => self.buf_0.get_waitting_buf_len_before_first_frame(),
            DIRECTION_1 => self.buf_1.get_waitting_buf_len_before_first_frame(),
            _ => unreachable!(),
        }
    }

    pub fn get_consequent_frame_size(&self, direction: u8) -> Option<usize> {
        match direction {
            DIRECTION_0 => self.buf_0.get_consequent_idx(),
            DIRECTION_1 => self.buf_1.get_consequent_idx(),
            _ => unreachable!(),
        }
    }

    pub fn get_consequent_buffer(
        &mut self,
        direction: u8,
    ) -> Option<(&mut [TcpFragementMeta], RingBufSlice<u8>)> {
        match direction {
            DIRECTION_0 => self.buf_0.get_consequent_buffer(),
            DIRECTION_1 => self.buf_1.get_consequent_buffer(),
            _ => unreachable!(),
        }
    }

    pub fn drain_frames(&mut self, direction: u8, n: usize) {
        match direction {
            DIRECTION_0 => self.buf_0.drain_frame_n(n),
            DIRECTION_1 => self.buf_1.drain_frame_n(n),
            _ => unreachable!(),
        };
    }

    pub fn flush_all_buf(
        &mut self,
    ) -> (
        Vec<(Vec<u8>, Vec<TcpFragementMeta>)>,
        Vec<(Vec<u8>, Vec<TcpFragementMeta>)>,
    ) {
        (self.buf_0.flush_all_buf(), self.buf_1.flush_all_buf())
    }
}
