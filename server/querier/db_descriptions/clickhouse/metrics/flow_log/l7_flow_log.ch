# Field              , DisplayName             , Unit , Description
request              , 请求                    , 个   ,
response             , 响应                    , 个   ,
session_length       , 会话长度                , 字节 , 请求长度 + 响应长度。
request_length       , 请求长度                , 字节 ,
response_length      , 响应长度                , 字节 ,
sql_affected_rows    , SQL 影响行数            , 行   ,
direction_score      , 方向得分                ,      , 算法推理应用协议请求方向时的准确性得分，得分越高请求方向的准确性越高，得分为 255 表示请求方向的推理结果绝对正确。
log_count            , 日志总量                , 个   ,

error                , 异常                    , 个   , `客户端异常 + 服务端异常`
client_error         , 客户端异常              , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
server_error         , 服务端异常              , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
error_ratio          , 异常比例                , %    , `异常 / 响应`
client_error_ratio   , 客户端异常比例          , %    , `客户端异常 / 响应`
server_error_ratio   , 服务端异常比例          , %    , `服务端异常 / 响应`

response_duration    , 响应时延                , 微秒 , 响应与请求的时间差

row                  , 行数                    , 个   ,     
