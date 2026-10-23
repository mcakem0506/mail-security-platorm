-- MSP 1.2: единственный Lua-файл сканера. Версионируется в Git и проходит ревью; из интерфейса и
-- базы Lua не принимается (ТЗ 1.2 §31).
--
-- Что делает (этап 1.2): регистрирует три символа направления письма. Направление задаёт слушатель Postfix
-- (отдельный сокет для входящих и исходящих), а правило настроек сканера только добавляет
-- символ в результат. Без регистрации сканер пишет в журнал «unknown symbol» на каждое письмо.
-- Разбора письма и записи файлов здесь нет. Единственное обращение к сети — запрос к локальной службе
-- принуждения (MSP 1.3, см. ниже), и только когда оно включено в настройках msp_enforcement.

local names = {
  MSP_DIRECTION_INBOUND = 'Входящее письмо (слушатель Postfix :25)',
  MSP_DIRECTION_OUTBOUND = 'Исходящее письмо (доверенный путь Exchange - шлюз)',
  MSP_DIRECTION_INTERNAL_TEST = 'Проверочное письмо стенда',
}

for name, description in pairs(names) do
  rspamd_config:register_symbol({
    name = name,
    score = 0.0,
    group = 'msp',
    description = description,
    type = 'virtual,skip',
    parent = rspamd_config:register_symbol({
      name = name .. '_CB',
      type = 'callback,empty',
      callback = function() return false end,
    }),
  })
end

-- MSP 1.3: шлюз принуждения до очереди (ТЗ 1.3 §11, §13, §14, §48).
--
-- Что делает: после подсчёта оценки отправляет локальной службе gateway-enforcement запись сканирования и получает
-- решение. Службу решает политика узла; здесь решения нет. Если служба отвечает REJECT или TEMPFAIL, письму
-- ставится предварительный результат с общим текстом ответа (без оценок, правил и топологии, §53).
-- Любая ошибка, тайм-аут или иной ответ — письмо идёт дальше (открытый сбой, §15): постоянный отказ из-за
-- внутренней ошибки невозможен. Включается только записью enabled = true в настройках msp_enforcement.
do
  local opts = rspamd_config:get_all_opt('msp_enforcement')
  if type(opts) == 'table' and opts.enabled == true and type(opts.url) == 'string' then
    local rspamd_http = require 'rspamd_http'
    local rspamd_logger = require 'rspamd_logger'
    local ucl = require 'ucl'
    local url = opts.url
    local timeout = tonumber(opts.timeout) or 1.5
    local module = 'msp_enforcement'

    rspamd_config:register_symbol({
      name = 'MSP_ENFORCEMENT_GATE',
      type = 'postfilter',
      priority = 10,
      score = 0.0,
      group = 'msp',
      description = 'Запрос решения у службы принуждения узла',
      callback = function(task)
        local symbols = {}
        for _, sym in ipairs(task:get_symbols_all() or {}) do
          table.insert(symbols, {
            name = sym.name,
            score = sym.score,
            group = sym.group,
            options = sym.options or {},
          })
        end
        local rcpt = {}
        for _, r in ipairs(task:get_recipients('smtp') or {}) do
          table.insert(rcpt, r.addr)
        end
        local from = task:get_from('smtp')
        local mime_from = task:get_from('mime')
        local score = task:get_metric_score()
        local ip = task:get_from_ip()
        local payload = {
          qid = task:get_queue_id() or 'unknown',
          message_id = task:get_message_id() or 'unknown',
          from = (from and from[1] and from[1].addr) or '',
          header_from = { (mime_from and mime_from[1] and mime_from[1].addr) or '' },
          rcpt = rcpt,
          ip = ip and tostring(ip) or 'unknown',
          helo = task:get_helo() or '',
          score = score and score[1] or 0.0,
          action = 'no action',
          symbols = symbols,
        }
        local body = ucl.to_format(payload, 'json-compact')

        local function done(err, code, resp)
          if err or code ~= 200 then
            rspamd_logger.warnx(task, 'msp_enforcement: служба недоступна (%s), письмо идёт дальше', err or code)
            return
          end
          local parser = ucl.parser()
          local ok = parser:parse_string(resp)
          if not ok then
            rspamd_logger.warnx(task, 'msp_enforcement: ответ не разобран, письмо идёт дальше')
            return
          end
          local answer = parser:get_object()
          local text = type(answer.reply) == 'string' and answer.reply or 'Message rejected by local policy'
          if answer.decision == 'REJECT' then
            task:set_pre_result('reject', text, module)
          elseif answer.decision == 'TEMPFAIL' then
            task:set_pre_result('soft reject', text, module)
          end
        end

        local ok = rspamd_http.request({
          task = task,
          url = url,
          method = 'POST',
          body = body,
          timeout = timeout,
          callback = done,
          headers = { ['Content-Type'] = 'application/json' },
        })
        if not ok then
          rspamd_logger.warnx(task, 'msp_enforcement: запрос не отправлен, письмо идёт дальше')
        end
      end,
    })
  end
end
