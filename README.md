# drivers.exe — утилита перечисления драйверов/сервисов/модулей ядра
<br>
Использование:<br>
  drivers.exe [--drivers] [--services] [--modules] [--all]<br>
             [--all-drivers]<br>
             [--search <substr>] [--out <file>]<br>
             <br>
По умолчанию, если без флагов, эквивалентно --all.<br>
  --drivers       : список драйверов (SERVICE_DRIVER)<br>
  --all-drivers   : показывать все драйверы (не только активные)<br>
  --services      : список обычных сервисов (SERVICE_WIN32)<br>
  --modules       : список модулей ядра (SystemModuleInformation)<br>
  --all           : всё сразу (drivers + services + modules)<br>
  --search, -s    : фильтр по имени/пути<br>
  --out, -o       : сохранить вывод в файл (UTF-8)<br>
  <br>
Примеры:<br>
  drivers.exe --all<br>
  drivers.exe --drivers --modules --search ntoskrnl<br>
  drivers.exe --drivers --all-drivers<br>
  drivers.exe --all --out report.txt<br>
