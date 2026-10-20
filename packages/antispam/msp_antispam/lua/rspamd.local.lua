-- MSP 1.2: единственный Lua-файл сканера. Версионируется в Git и проходит ревью; из интерфейса и
-- базы Lua не принимается (ТЗ 1.2 §31).
--
-- Что делает: регистрирует три символа направления письма. Направление задаёт слушатель Postfix
-- (отдельный сокет для входящих и исходящих), а правило настроек сканера только добавляет
-- символ в результат. Без регистрации сканер пишет в журнал «unknown symbol» на каждое письмо.
-- Никакой логики разбора письма, обращений к сети и записи файлов здесь нет.

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
