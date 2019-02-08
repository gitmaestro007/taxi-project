<?php
///////////////////////////////////////////////////////////////////////////
// Version: SOME_VERSION
// Created and developed by Greg Zemskov, Revisium Company
// Email: audit@revisium.com, http://revisium.com/ai/

// Commercial usage is not allowed without a license purchase or written permission of the author
// Source code and signatures usage is not allowed

// Certificated in Federal Institute of Industrial Property in 2012
// http://revisium.com/ai/i/mini_aibolit.jpg

////////////////////////////////////////////////////////////////////////////
// Запрещено использование скрипта в коммерческих целях без приобретения лицензии.
// Запрещено использование исходного кода скрипта и сигнатур.
//
// По вопросам приобретения лицензии обращайтесь в компанию "Ревизиум": http://www.revisium.com
// audit@revisium.com
// На скрипт получено авторское свидетельство в Роспатенте
// http://revisium.com/ai/i/mini_aibolit.jpg
///////////////////////////////////////////////////////////////////////////
ini_set('memory_limit', '1G');
ini_set('xdebug.max_nesting_level', 500);

$int_enc = @ini_get('mbstring.internal_encoding');

define('SHORT_PHP_TAG', strtolower(ini_get('short_open_tag')) == 'on' || strtolower(ini_get('short_open_tag')) == 1 ? true : false);

// Put any strong password to open the script from web
// Впишите вместо put_any_strong_password_here сложный пароль	 

define('PASS', '????????????????');

//////////////////////////////////////////////////////////////////////////

if (isCli()) {
    if (strpos('--eng', $argv[$argc - 1]) !== false) {
        define('LANG', 'EN');
    }
} else {
    if (PASS == '????????????????') {
       die('Forbidden'); 
    }

    define('NEED_REPORT', true);
}

if (!defined('LANG')) {
    define('LANG', 'RU');
}

// put 1 for expert mode, 0 for basic check and 2 for paranoid mode
// установите 1 для режима "Обычное сканирование", 0 для быстрой проверки и 2 для параноидальной проверки (диагностика при лечении сайтов) 
define('AI_EXPERT_MODE', 2);

define('REPORT_MASK_DOORWAYS', 4);
define('REPORT_MASK_FULL', 0); # REPORT_MASK_DOORWAYS);

define('AI_HOSTER', 1);

define('AI_EXTRA_WARN', 0);

$defaults = array(
    'path' => dirname(__FILE__),
    'scan_all_files' => (AI_EXPERT_MODE == 2), // full scan (rather than just a .js, .php, .html, .htaccess)
    'scan_delay' => 0, // delay in file scanning to reduce system load
    'max_size_to_scan' => '650K',
    'site_url' => '', // website url
    'no_rw_dir' => 0,
    'skip_ext' => '',
    'skip_cache' => false,
    'report_mask' => REPORT_MASK_FULL
);

define('DEBUG_MODE', 0);
define('DEBUG_PERFORMANCE', 0);

define('AIBOLIT_START_TIME', time());
define('START_TIME', microtime(true));

define('DIR_SEPARATOR', '/');

define('AIBOLIT_MAX_NUMBER', 200);

define('DOUBLECHECK_FILE', 'AI-BOLIT-DOUBLECHECK.php');

if ((isset($_SERVER['OS']) && stripos('Win', $_SERVER['OS']) !== false)) {
    define('DIR_SEPARATOR', '\\');
}

$g_SuspiciousFiles = array(
    'cgi',
    'pl',
    'o',
    'so',
    'py',
    'sh',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php6',
    'php7',
    'pht',
    'shtml'
);
$g_SensitiveFiles  = array_merge(array(
    'php',
    'js',
    'json',
    'htaccess',
    'html',
    'htm',
    'tpl',
    'inc',
    'css',
    'txt',
    'sql',
    'ico',
    '',
    'susp',
    'suspected',
    'zip',
    'tar'
), $g_SuspiciousFiles);
$g_CriticalFiles   = array(
    'php',
    'htaccess',
    'cgi',
    'pl',
    'o',
    'so',
    'py',
    'sh',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php6',
    'php7',
    'pht',
    'shtml',
    'susp',
    'suspected',
    'infected',
    'vir',
    'ico',
    'js',
    'json',  
    ''
);
$g_CriticalEntries = '^\s*<\?php|^\s*<\?=|^#!/usr|^#!/bin|\beval|assert|base64_decode|\bsystem|create_function|\bexec|\bpopen|\bfwrite|\bfputs|file_get_|call_user_func|file_put_|\$_REQUEST|ob_start|\$_GET|\$_POST|\$_SERVER|\$_FILES|\bmove|\bcopy|\barray_|reg_replace|\bmysql_|\bchr|fsockopen|\$GLOBALS|sqliteCreateFunction';
$g_VirusFiles      = array(
    'js',
    'json', 
    'html',
    'htm',
    'suspicious'
);
$g_VirusEntries    = '<script|<iframe|<object|<embed|fromCharCode|setTimeout|setInterval|location\.|document\.|window\.|navigator\.|\$(this)\.';
$g_PhishFiles      = array(
    'js',
    'html',
    'htm',
    'suspected',
    'php',
    'phtml',
    'pht',
    'php7'
);
$g_PhishEntries    = '<\s*title|<\s*html|<\s*form|<\s*body|bank|account';
$g_ShortListExt    = array(
    'php',
    'php3',
    'php4',
    'php5',
    'php7',
    'pht',
    'html',
    'htm',
    'phtml',
    'shtml',
    'khtml',
    '',
    'ico',
    'txt'
);

if (LANG == 'RU') {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // RUSSIAN INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Отображать по _MENU_ записей\"";
    $msg2  = "\"Ничего не найдено\"";
    $msg3  = "\"Отображается c _START_ по _END_ из _TOTAL_ файлов\"";
    $msg4  = "\"Нет файлов\"";
    $msg5  = "\"(всего записей _MAX_)\"";
    $msg6  = "\"Поиск:\"";
    $msg7  = "\"Первая\"";
    $msg8  = "\"Предыдущая\"";
    $msg9  = "\"Следующая\"";
    $msg10 = "\"Последняя\"";
    $msg11 = "\": активировать для сортировки столбца по возрастанию\"";
    $msg12 = "\": активировать для сортировки столбцов по убыванию\"";
    
    define('AI_STR_001', 'Отчет сканера <a href="https://revisium.com/ai/">AI-Bolit</a> v@@VERSION@@:');
    define('AI_STR_002', 'Обращаем внимание на то, что большинство CMS <b>без дополнительной защиты</b> рано или поздно <b>взламывают</b>.<p> Компания <a href="https://revisium.com/">"Ревизиум"</a> предлагает услугу превентивной защиты сайта от взлома с использованием уникальной <b>процедуры "цементирования сайта"</b>. Подробно на <a href="https://revisium.com/ru/client_protect/">странице услуги</a>. <p>Лучшее лечение &mdash; это профилактика.');
    define('AI_STR_003', 'Не оставляйте файл отчета на сервере, и не давайте на него прямых ссылок с других сайтов. Информация из отчета может быть использована злоумышленниками для взлома сайта, так как содержит информацию о настройках сервера, файлах и каталогах.');
    define('AI_STR_004', 'Путь');
    define('AI_STR_005', 'Изменение свойств');
    define('AI_STR_006', 'Изменение содержимого');
    define('AI_STR_007', 'Размер');
    define('AI_STR_008', 'Конфигурация PHP');
    define('AI_STR_009', "Вы установили слабый пароль на скрипт AI-BOLIT. Укажите пароль не менее 8 символов, содержащий латинские буквы в верхнем и нижнем регистре, а также цифры. Например, такой <b>%s</b>");
    define('AI_STR_010', "Сканер AI-Bolit запускается с паролем. Если это первый запуск сканера, вам нужно придумать сложный пароль и вписать его в файле ai-bolit.php в строке №34. <p>Например, <b>define('PASS', '%s');</b><p>
После этого откройте сканер в браузере, указав пароль в параметре \"p\". <p>Например, так <b>http://mysite.ru/ai-bolit.php?p=%s</b>. ");
    define('AI_STR_011', 'Текущая директория не доступна для чтения скрипту. Пожалуйста, укажите права на доступ <b>rwxr-xr-x</b> или с помощью командной строки <b>chmod +r имя_директории</b>');
    define('AI_STR_012', "Затрачено времени: <b>%s</b>. Сканирование начато %s, сканирование завершено %s");
    define('AI_STR_013', 'Всего проверено %s директорий и %s файлов.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Внимание, скрипт выполнил быструю проверку сайта. Проверяются только наиболее критические файлы, но часть вредоносных скриптов может быть не обнаружена. Пожалуйста, запустите скрипт из командной строки для выполнения полного тестирования. Подробнее смотрите в <a href="https://revisium.com/ai/faq.php">FAQ вопрос №10</a>.</div>');
    define('AI_STR_015', '<div class="title">Критические замечания</div>');
    define('AI_STR_016', 'Эти файлы могут быть вредоносными или хакерскими скриптами');
    define('AI_STR_017', 'Вирусы и вредоносные скрипты не обнаружены.');
    define('AI_STR_018', 'Эти файлы могут быть javascript вирусами');
    define('AI_STR_019', 'Обнаружены сигнатуры исполняемых файлов unix и нехарактерных скриптов. Они могут быть вредоносными файлами');
    define('AI_STR_020', 'Двойное расширение, зашифрованный контент или подозрение на вредоносный скрипт. Требуется дополнительный анализ');
    define('AI_STR_021', 'Подозрение на вредоносный скрипт');
    define('AI_STR_022', 'Символические ссылки (symlinks)');
    define('AI_STR_023', 'Скрытые файлы');
    define('AI_STR_024', 'Возможно, каталог с дорвеем');
    define('AI_STR_025', 'Не найдено директорий c дорвеями');
    define('AI_STR_026', 'Предупреждения');
    define('AI_STR_027', 'Подозрение на мобильный редирект, подмену расширений или автовнедрение кода');
    define('AI_STR_028', 'В не .php файле содержится стартовая сигнатура PHP кода. Возможно, там вредоносный код');
    define('AI_STR_029', 'Дорвеи, реклама, спам-ссылки, редиректы');
    define('AI_STR_030', 'Непроверенные файлы - ошибка чтения');
    define('AI_STR_031', 'Невидимые ссылки. Подозрение на ссылочный спам');
    define('AI_STR_032', 'Невидимые ссылки');
    define('AI_STR_033', 'Отображены только первые ');
    define('AI_STR_034', 'Подозрение на дорвей');
    define('AI_STR_035', 'Скрипт использует код, который часто встречается во вредоносных скриптах');
    define('AI_STR_036', 'Директории из файла .adirignore были пропущены при сканировании');
    define('AI_STR_037', 'Версии найденных CMS');
    define('AI_STR_038', 'Большие файлы (больше чем %s). Пропущено');
    define('AI_STR_039', 'Не найдено файлов больше чем %s');
    define('AI_STR_040', 'Временные файлы или файлы(каталоги) - кандидаты на удаление по ряду причин');
    define('AI_STR_041', 'Потенциально небезопасно! Директории, доступные скрипту на запись');
    define('AI_STR_042', 'Не найдено директорий, доступных на запись скриптом');
    define('AI_STR_043', 'Использовано памяти при сканировании: ');
    define('AI_STR_044', 'Просканированы только файлы, перечисленные в ' . DOUBLECHECK_FILE . '. Для полного сканирования удалите файл ' . DOUBLECHECK_FILE . ' и запустите сканер повторно.');
    define('AI_STR_045', '<div class="rep">Внимание! Выполнена экспресс-проверка сайта. Просканированы только файлы с расширением .php, .js, .html, .htaccess. В этом режиме могут быть пропущены вирусы и хакерские скрипты в файлах с другими расширениями. Чтобы выполнить более тщательное сканирование, поменяйте значение настройки на <b>\'scan_all_files\' => 1</b> в строке 50 или откройте сканер в браузере с параметром full: <b><a href="ai-bolit.php?p=' . PASS . '&full">ai-bolit.php?p=' . PASS . '&full</a></b>. <p>Не забудьте перед повторным запуском удалить файл ' . DOUBLECHECK_FILE . '</div>');
    define('AI_STR_050', 'Замечания и предложения по работе скрипта и не обнаруженные вредоносные скрипты присылайте на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<p>Также будем чрезвычайно благодарны за любые упоминания скрипта AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. Ссылочку можно поставить на <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>. <p>Если будут вопросы - пишите <a href="mailto:ai@revisium.com">ai@revisium.com</a>. ');
    define('AI_STR_051', 'Отчет по ');
    define('AI_STR_052', 'Эвристический анализ обнаружил подозрительные файлы. Проверьте их на наличие вредоносного кода.');
    define('AI_STR_053', 'Много косвенных вызовов функции');
    define('AI_STR_054', 'Подозрение на обфусцированные переменные');
    define('AI_STR_055', 'Подозрительное использование массива глобальных переменных');
    define('AI_STR_056', 'Дробление строки на символы');
    define('AI_STR_057', 'Сканирование выполнено в экспресс-режиме. Многие вредоносные скрипты могут быть не обнаружены.<br> Рекомендуем проверить сайт в режиме "Эксперт" или "Параноидальный". Подробно описано в <a href="https://revisium.com/ai/faq.php">FAQ</a> и инструкции к скрипту.');
    define('AI_STR_058', 'Обнаружены фишинговые страницы');
    
    define('AI_STR_059', 'Мобильных редиректов');
    define('AI_STR_060', 'Вредоносных скриптов');
    define('AI_STR_061', 'JS Вирусов');
    define('AI_STR_062', 'Фишинговых страниц');
    define('AI_STR_063', 'Исполняемых файлов');
    define('AI_STR_064', 'IFRAME вставок');
    define('AI_STR_065', 'Пропущенных больших файлов');
    define('AI_STR_066', 'Ошибок чтения файлов');
    define('AI_STR_067', 'Зашифрованных файлов');
    define('AI_STR_068', 'Подозрительных (эвристика)');
    define('AI_STR_069', 'Символических ссылок');
    define('AI_STR_070', 'Скрытых файлов');
    define('AI_STR_072', 'Рекламных ссылок и кодов');
    define('AI_STR_073', 'Пустых ссылок');
    define('AI_STR_074', 'Сводный отчет');
    define('AI_STR_075', 'Сканер бесплатный только для личного некоммерческого использования. Информация по <a href="https://revisium.com/ai/faq.php#faq11" target=_blank>коммерческой лицензии</a> (пункт №11). <a href="https://revisium.com/images/mini_aibolit.jpg">Авторское свидетельство</a> о гос. регистрации в РосПатенте №2012619254 от 12 октября 2012 г.');
    
    $tmp_str = <<<HTML_FOOTER
   <div class="disclaimer"><span class="vir">[!]</span> Отказ от гарантий: невозможно гарантировать обнаружение всех вредоносных скриптов. Поэтому разработчик сканера не несет ответственности за возможные последствия работы сканера AI-Bolit или неоправданные ожидания пользователей относительно функциональности и возможностей.
   </div>
   <div class="thanx">
      Замечания и предложения по работе скрипта, а также не обнаруженные вредоносные скрипты вы можете присылать на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<br/>
      Также будем чрезвычайно благодарны за любые упоминания сканера AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. <br/>Ссылку можно поставить на страницу <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>.<br/> 
     <p>Получить консультацию или задать вопросы можно по email <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
	</div>
HTML_FOOTER;
    
    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Подозрительные параметры времени изменения файла");
    define('AI_STR_078', "Подозрительные атрибуты файла");
    define('AI_STR_079', "Подозрительное местоположение файла");
    define('AI_STR_080', "Обращаем внимание, что обнаруженные файлы не всегда являются вирусами и хакерскими скриптами. Сканер минимизирует число ложных обнаружений, но это не всегда возможно, так как найденный фрагмент может встречаться как во вредоносных скриптах, так и в обычных.<p>Для диагностического сканирования без ложных срабатываний мы разработали специальную версию <u><a href=\"https://revisium.com/ru/blog/ai-bolit-4-ISP.html\" target=_blank style=\"background: none; color: #303030\">сканера для хостинг-компаний</a></u>.");
    define('AI_STR_081', "Уязвимости в скриптах");
    define('AI_STR_082', "Добавленные файлы");
    define('AI_STR_083', "Измененные файлы");
    define('AI_STR_084', "Удаленные файлы");
    define('AI_STR_085', "Добавленные каталоги");
    define('AI_STR_086', "Удаленные каталоги");
    define('AI_STR_087', "Изменения в файловой структуре");
    
    $l_Offer = <<<OFFER
    <div>
	 <div class="crit" style="font-size: 17px; margin-bottom: 20px"><b>Внимание! Наш сканер обнаружил подозрительный или вредоносный код</b>.</div> 
	 <p>Возможно, ваш сайт был взломан. Рекомендуем срочно <a href="https://revisium.com/ru/order/#fform" target=_blank>проконсультироваться со специалистами</a> по данному отчету.</p>
	 <p><hr size=1></p>
	 <p>Рекомендуем также проверить сайт бесплатным <b><a href="https://rescan.pro/?utm=aibolit" target=_blank>онлайн-сканером ReScan.Pro</a></b>.</p>
	 <p><hr size=1></p>
         <div class="caution">@@CAUTION@@</div>
    </div>
OFFER;
    
    $l_Offer2 = <<<OFFER2
	   <b>Наши продукты:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="https://revisium.com/ru/products/antivirus_for_ispmanager/" target=_blank>Антивирус для ISPmanager Lite</a></b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/blog/revisium-antivirus-for-plesk.html" target=_blank>Антивирус для Plesk</a> Onyx 17.x</b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://cloudscan.pro/ru/" target=_blank>Облачный антивирус CloudScan.Pro</a> для веб-специалистов</b> &mdash; лечение сайтов в один клик</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/antivirus-server/" target=_blank>Антивирус для сервера</a></b> &mdash; для хостин-компаний, веб-студий и агентств.</li>
              </ul>  
	</div>
OFFER2;
    
} else {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // ENGLISH INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Display _MENU_ records\"";
    $msg2  = "\"Not found\"";
    $msg3  = "\"Display from _START_ to _END_ of _TOTAL_ files\"";
    $msg4  = "\"No files\"";
    $msg5  = "\"(total _MAX_)\"";
    $msg6  = "\"Filter/Search:\"";
    $msg7  = "\"First\"";
    $msg8  = "\"Previous\"";
    $msg9  = "\"Next\"";
    $msg10 = "\"Last\"";
    $msg11 = "\": activate to sort row ascending order\"";
    $msg12 = "\": activate to sort row descending order\"";
    
    define('AI_STR_001', 'AI-Bolit v@@VERSION@@ Scan Report:');
    define('AI_STR_002', '');
    define('AI_STR_003', 'Caution! Do not leave either ai-bolit.php or report file on server and do not provide direct links to the report file. Report file contains sensitive information about your website which could be used by hackers. So keep it in safe place and don\'t leave on website!');
    define('AI_STR_004', 'Path');
    define('AI_STR_005', 'iNode Changed');
    define('AI_STR_006', 'Modified');
    define('AI_STR_007', 'Size');
    define('AI_STR_008', 'PHP Info');
    define('AI_STR_009', "Your password for AI-BOLIT is too weak. Password must be more than 8 character length, contain both latin letters in upper and lower case, and digits. E.g. <b>%s</b>");
    define('AI_STR_010', "Open AI-BOLIT with password specified in the beggining of file in PASS variable. <br/>E.g. http://you_website.com/ai-bolit.php?p=<b>%s</b>");
    define('AI_STR_011', 'Current folder is not readable. Please change permission for <b>rwxr-xr-x</b> or using command line <b>chmod +r folder_name</b>');
    define('AI_STR_012', "<div class=\"rep\">%s malicious signatures known, %s virus signatures and other malicious code. Elapsed: <b>%s</b
>.<br/>Started: %s. Stopped: %s</div> ");
    define('AI_STR_013', 'Scanned %s folders and %s files.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Attention! Script has performed quick scan. It scans only .html/.js/.php files  in quick scan mode so some of malicious scripts might not be detected. <br>Please launch script from a command line thru SSH to perform full scan.');
    define('AI_STR_015', '<div class="title">Critical</div>');
    define('AI_STR_016', 'Shell script signatures detected. Might be a malicious or hacker\'s scripts');
    define('AI_STR_017', 'Shell scripts signatures not detected.');
    define('AI_STR_018', 'Javascript virus signatures detected:');
    define('AI_STR_019', 'Unix executables signatures and odd scripts detected. They might be a malicious binaries or rootkits:');
    define('AI_STR_020', 'Suspicious encoded strings, extra .php extention or external includes detected in PHP files. Might be a malicious or hacker\'s script:');
    define('AI_STR_021', 'Might be a malicious or hacker\'s script:');
    define('AI_STR_022', 'Symlinks:');
    define('AI_STR_023', 'Hidden files:');
    define('AI_STR_024', 'Files might be a part of doorway:');
    define('AI_STR_025', 'Doorway folders not detected');
    define('AI_STR_026', 'Warnings');
    define('AI_STR_027', 'Malicious code in .htaccess (redirect to external server, extention handler replacement or malicious code auto-append):');
    define('AI_STR_028', 'Non-PHP file has PHP signature. Check for malicious code:');
    define('AI_STR_029', 'This script has black-SEO links or linkfarm. Check if it was installed by yourself:');
    define('AI_STR_030', 'Reading error. Skipped.');
    define('AI_STR_031', 'These files have invisible links, might be black-seo stuff:');
    define('AI_STR_032', 'List of invisible links:');
    define('AI_STR_033', 'Displayed first ');
    define('AI_STR_034', 'Folders contained too many .php or .html files. Might be a doorway:');
    define('AI_STR_035', 'Suspicious code detected. It\'s usually used in malicious scrips:');
    define('AI_STR_036', 'The following list of files specified in .adirignore has been skipped:');
    define('AI_STR_037', 'CMS found:');
    define('AI_STR_038', 'Large files (greater than %s! Skipped:');
    define('AI_STR_039', 'Files greater than %s not found');
    define('AI_STR_040', 'Files recommended to be remove due to security reason:');
    define('AI_STR_041', 'Potentially unsafe! Folders which are writable for scripts:');
    define('AI_STR_042', 'Writable folders not found');
    define('AI_STR_043', 'Memory used: ');
    define('AI_STR_044', 'Quick scan through the files from ' . DOUBLECHECK_FILE . '. For full scan remove ' . DOUBLECHECK_FILE . ' and launch scanner once again.');
    define('AI_STR_045', '<div class="notice"><span class="vir">[!]</span> Ai-BOLIT is working in quick scan mode, only .php, .html, .htaccess files will be checked. Change the following setting \'scan_all_files\' => 1 to perform full scanning.</b>. </div>');
    define('AI_STR_050', "I'm sincerely appreciate reports for any bugs you may found in the script. Please email me: <a href=\"mailto:audit@revisium.com\">audit@revisium.com</a>.<p> Also I appriciate any reference to the script in your blog or forum posts. Thank you for the link to download page: <a href=\"https://revisium.com/aibo/\">https://revisium.com/aibo/</a>");
    define('AI_STR_051', 'Report for ');
    define('AI_STR_052', 'Heuristic Analyzer has detected suspicious files. Check if they are malware.');
    define('AI_STR_053', 'Function called by reference');
    define('AI_STR_054', 'Suspected for obfuscated variables');
    define('AI_STR_055', 'Suspected for $GLOBAL array usage');
    define('AI_STR_056', 'Abnormal split of string');
    define('AI_STR_057', 'Scanning has been done in simple mode. It is strongly recommended to perform scanning in "Expert" mode. See readme.txt for details.');
    define('AI_STR_058', 'Phishing pages detected:');
    
    define('AI_STR_059', 'Mobile redirects');
    define('AI_STR_060', 'Malware');
    define('AI_STR_061', 'JS viruses');
    define('AI_STR_062', 'Phishing pages');
    define('AI_STR_063', 'Unix executables');
    define('AI_STR_064', 'IFRAME injections');
    define('AI_STR_065', 'Skipped big files');
    define('AI_STR_066', 'Reading errors');
    define('AI_STR_067', 'Encrypted files');
    define('AI_STR_068', 'Suspicious (heuristics)');
    define('AI_STR_069', 'Symbolic links');
    define('AI_STR_070', 'Hidden files');
    define('AI_STR_072', 'Adware and spam links');
    define('AI_STR_073', 'Empty links');
    define('AI_STR_074', 'Summary');
    define('AI_STR_075', 'For non-commercial use only. In order to purchase the commercial license of the scanner contact us at ai@revisium.com');
    
    $tmp_str = <<<HTML_FOOTER
		   <div class="disclaimer"><span class="vir">[!]</span> Disclaimer: We're not liable to you for any damages, including general, special, incidental or consequential damages arising out of the use or inability to use the script (including but not limited to loss of data or report being rendered inaccurate or failure of the script). There's no warranty for the program. Use at your own risk. 
		   </div>
		   <div class="thanx">
		      We're greatly appreciate for any references in the social medias, forums or blogs to our scanner AI-BOLIT <a href="https://revisium.com/aibo/">https://revisium.com/aibo/</a>.<br/> 
		     <p>Contact us via email if you have any questions regarding the scanner or need report analysis: <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
			</div>
HTML_FOOTER;
    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Suspicious file mtime and ctime");
    define('AI_STR_078', "Suspicious file permissions");
    define('AI_STR_079', "Suspicious file location");
    define('AI_STR_081', "Vulnerable Scripts");
    define('AI_STR_082', "Added files");
    define('AI_STR_083', "Modified files");
    define('AI_STR_084', "Deleted files");
    define('AI_STR_085', "Added directories");
    define('AI_STR_086', "Deleted directories");
    define('AI_STR_087', "Integrity Check Report");
    
    $l_Offer = <<<HTML_OFFER_EN
<div>
 <div class="crit" style="font-size: 17px;"><b>Attention! The scanner has detected suspicious or malicious files.</b></div> 
 <br/>Most likely the website has been compromised. Please, <a href="https://revisium.com/en/contacts/" target=_blank>contact web security experts</a> from Revisium to check the report or clean the malware.
 <p><hr size=1></p>
 Also check your website for viruses with our free <b><a href="http://rescan.pro/?en&utm=aibo" target=_blank>online scanner ReScan.Pro</a></b>.
</div>
<br/>
<div>
   Revisium contacts: <a href="mailto:ai@revisium.com">ai@revisium.com</a>, <a href="https://revisium.com/en/contacts/">https://revisium.com/en/home/</a>
</div>
<div class="caution">@@CAUTION@@</div>
HTML_OFFER_EN;
    
    $l_Offer2 = '<b>Special Offers:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="http://ext.plesk.com/packages/b71916cf-614e-4b11-9644-a5fe82060aaf-revisium-antivirus">Antivirus for Plesk Onyx</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px"><font color=red></font><b><a href="https://www.ispsystem.com/addons-modules/revisium">Antivirus for ISPmanager Lite</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px">Professional malware cleanup and web-protection service with 6 month guarantee for only $99 (one-time payment): <a href="https://revisium.com/en/home/#order_form">https://revisium.com/en/home/</a>.</li>
              </ul>  
	</div>';
    
    define('AI_STR_080', "Notice! Some of detected files may not contain malicious code. Scanner tries to minimize a number of false positives, but sometimes it's impossible, because same piece of code may be used either in malware or in normal scripts.");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$l_Template = <<<MAIN_PAGE
<html>
<head>
<!-- revisium.com/ai/ -->
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" >
<META NAME="ROBOTS" CONTENT="NOINDEX,NOFOLLOW">
<title>@@HEAD_TITLE@@</title>
<style type="text/css" title="currentStyle">
	@import "https://cdn.revisium.com/ai/media/css/demo_page2.css";
	@import "https://cdn.revisium.com/ai/media/css/jquery.dataTables2.css";
</style>

<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/jquery.js"></script>
<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/datatables.min.js"></script>

<style type="text/css">
 body 
 {
   font-family: Tahoma;
   color: #5a5a5a;
   background: #FFFFFF;
   font-size: 14px;
   margin: 20px;
   padding: 0;
 }

.header
 {
   font-size: 34px;
   margin: 0 0 10px 0;
 }

 .hidd
 {
    display: none;
 }
 
 .ok
 {
    color: green;
 }
 
 .line_no
 {
   -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #DAF2C1;
   padding: 2px 5px 2px 5px;
   margin: 0 5px 0 5px;
 }
 
 .credits_header 
 {
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #F2F2F2;
   padding: 10px;
   font-size: 11px;
    margin: 0 0 10px 0;
 }
 
 .marker
 {
    color: #FF0090;
	font-weight: 100;
	background: #FF0090;
	padding: 2px 0px 2px 0px;
	width: 2px;
 }
 
 .title
 {
   font-size: 24px;
   margin: 20px 0 10px 0;
   color: #9CA9D1;
}

.summary 
{
  float: left;
  width: 500px;
}

.summary TD
{
  font-size: 12px;
  border-bottom: 1px solid #F0F0F0;
  font-weight: 700;
  padding: 10px 0 10px 0;
}
 
.crit, .vir
{
  color: #D84B55;
}

.intitem
{
  color:#4a6975;
}

.spacer
{
   margin: 0 0 50px 0;
   clear:both;
}

.warn
{
  color: #F6B700;
}

.clear
{
   clear: both;
}

.offer
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #F2F2F2;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}

.offer2
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #f6f5e0;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}


HR {
  margin-top: 15px;
  margin-bottom: 15px;
  opacity: .2;
}
 
.flist
{
   font-family: Henvetica, Arial;
}

.flist TD
{
   font-size: 11px;
   padding: 5px;
}

.flist TH
{
   font-size: 12px;
   height: 30px;
   padding: 5px;
   background: #CEE9EF;
}


.it
{
   font-size: 14px;
   font-weight: 100;
   margin-top: 10px;
}

.crit .it A {
   color: #E50931; 
   line-height: 25px;
   text-decoration: none;
}

.warn .it A {
   color: #F2C900; 
   line-height: 25px;
   text-decoration: none;
}



.details
{
   font-family: Calibri;
   font-size: 12px;
   margin: 10px 10px 10px 0px;
}

.crit .details
{
   color: #A08080;
}

.warn .details
{
   color: #808080;
}

.details A
{
  color: #FFF;
  font-weight: 700;
  text-decoration: none;
  padding: 2px;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;
}

.details A:hover
{
   background: #A0909B;
}

.ctd
{
   margin: 10px 0px 10px 0;
   align:center;
}

.ctd A 
{
   color: #0D9922;
}

.disclaimer
{
   color: darkgreen;
   margin: 10px 10px 10px 0;
}

.note_vir
{
   margin: 10px 0 10px 0;
   //padding: 10px;
   color: #FF4F4F;
   font-size: 15px;
   font-weight: 700;
   clear:both;
  
}

.note_warn
{
   margin: 10px 0 10px 0;
   color: #F6B700;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.note_int
{
   margin: 10px 0 10px 0;
   color: #60b5d6;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.updateinfo
{
  color: #FFF;
  text-decoration: none;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
}


.caution
{
  color: #EF7B75;
  text-decoration: none;
  margin: 20px 0 0px 0px;   
  font-size: 12px;
}

.footer
{
  color: #303030;
  text-decoration: none;
  background: #F4F4F4;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 80px 0 10px 0px;   
  padding: 10px;
}

.rep
{
  color: #303030;
  text-decoration: none;
  background: #94DDDB;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
  font-size: 12px;
}

</style>

</head>
<body>

<div class="header">@@MAIN_TITLE@@ @@PATH_URL@@ (@@MODE@@)</div>
<div class="credits_header">@@CREDITS@@</div>
<div class="details_header">
   @@STAT@@<br/>
   @@SCANNED@@ @@MEMORY@@.
 </div>

 @@WARN_QUICK@@
 
 <div class="summary">
@@SUMMARY@@
 </div>
 
 <div class="offer">
@@OFFER@@
 </div>

 <div class="offer2">
@@OFFER2@@
 </div> 
 
 <div class="clear"></div>
 
 @@MAIN_CONTENT@@
 
	<div class="footer">
	@@FOOTER@@
	</div>
	
<script language="javascript">

function hsig(id) {
  var divs = document.getElementsByTagName("tr");
  for(var i = 0; i < divs.length; i++){
     
     if (divs[i].getAttribute('o') == id) {
        divs[i].innerHTML = '';
     }
  }

  return false;
}


$(document).ready(function(){
    $('#table_crit').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
		"paging": true,
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending": $msg11,
				"sSortDescending": $msg12	
			}
		}

     } );

});

$(document).ready(function(){
    $('#table_vir').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending":  $msg11,
				"sSortDescending": $msg12	
			}
		},

     } );

});

if ($('#table_warn0')) {
    $('#table_warn0').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}

if ($('#table_warn1')) {
    $('#table_warn1').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}


</script>
<!-- @@SERVICE_INFO@@  -->
 </body>
</html>
MAIN_PAGE;

$g_AiBolitAbsolutePath = dirname(__FILE__);

if (file_exists($g_AiBolitAbsolutePath . '/ai-design.html')) {
    $l_Template = file_get_contents($g_AiBolitAbsolutePath . '/ai-design.html');
}

$l_Template = str_replace('@@MAIN_TITLE@@', AI_STR_001, $l_Template);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$g_Mnemo = array();

//BEGIN_SIG 05/02/2019 08:08:49
$g_DBShe = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$gX_DBShe = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_FlexDBShe = unserialize(gzinflate(/*1549386529*/base64_decode("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")));
$gX_FlexDBShe = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$gXX_FlexDBShe = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_ExceptFlex = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_AdwareSig = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_PhishingSig = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_JSVirSig = unserialize(gzinflate(/*1549386529*/base64_decode("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")));
$gX_JSVirSig = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_SusDB = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_SusDBPrio = unserialize(gzinflate(/*1549386529*/base64_decode("S7QysKquBQA=")));
$g_Mnemo = @array_flip(unserialize(gzinflate(/*1549386529*/base64_decode("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"))));
$g_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));

//END_SIG
////////////////////////////////////////////////////////////////////////////
if (!isCli() && !isset($_SERVER['HTTP_USER_AGENT'])) {
    echo "#####################################################\n";
    echo "# Error: cannot run on php-cgi. Requires php as cli #\n";
    echo "#                                                   #\n";
    echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
    echo "#####################################################\n";
    exit;
}


if (version_compare(phpversion(), '5.3.1', '<')) {
    echo "#####################################################\n";
    echo "# Warning: PHP Version < 5.3.1                      #\n";
    echo "# Some function might not work properly             #\n";
    echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
    echo "#####################################################\n";
    exit;
}

if (!(function_exists("file_put_contents") && is_callable("file_put_contents"))) {
    echo "#####################################################\n";
    echo "file_put_contents() is disabled. Cannot proceed.\n";
    echo "#####################################################\n";
    exit;
}

define('AI_VERSION', 'HOSTER-20190205-1708');

////////////////////////////////////////////////////////////////////////////

$l_Res = '';

$g_Structure = array();
$g_Counter   = 0;

$g_SpecificExt = false;

$g_UpdatedJsonLog    = 0;
$g_NotRead           = array();
$g_FileInfo          = array();
$g_Iframer           = array();
$g_PHPCodeInside     = array();
$g_CriticalJS        = array();
$g_Phishing          = array();
$g_Base64            = array();
$g_HeuristicDetected = array();
$g_HeuristicType     = array();
$g_UnixExec          = array();
$g_SkippedFolders    = array();
$g_UnsafeFilesFound  = array();
$g_CMS               = array();
$g_SymLinks          = array();
$g_HiddenFiles       = array();
$g_Vulnerable        = array();

$g_RegExpStat = array();

$g_TotalFolder = 0;
$g_TotalFiles  = 0;

$g_FoundTotalDirs  = 0;
$g_FoundTotalFiles = 0;

if (!isCli()) {
    $defaults['site_url'] = 'http://' . $_SERVER['HTTP_HOST'] . '/';
}

define('CRC32_LIMIT', pow(2, 31) - 1);
define('CRC32_DIFF', CRC32_LIMIT * 2 - 2);

error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);
srand(time());

set_time_limit(0);
ini_set('max_execution_time', '900000');
ini_set('realpath_cache_size', '16M');
ini_set('realpath_cache_ttl', '1200');
ini_set('pcre.backtrack_limit', '1000000');
ini_set('pcre.recursion_limit', '200000');
ini_set('pcre.jit', '1');

if (!function_exists('stripos')) {
    function stripos($par_Str, $par_Entry, $Offset = 0) {
        return strpos(strtolower($par_Str), strtolower($par_Entry), $Offset);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
define('CMS_BITRIX', 'Bitrix');
define('CMS_WORDPRESS', 'WordPress');
define('CMS_JOOMLA', 'Joomla');
define('CMS_DLE', 'Data Life Engine');
define('CMS_IPB', 'Invision Power Board');
define('CMS_WEBASYST', 'WebAsyst');
define('CMS_OSCOMMERCE', 'OsCommerce');
define('CMS_DRUPAL', 'Drupal');
define('CMS_MODX', 'MODX');
define('CMS_INSTANTCMS', 'Instant CMS');
define('CMS_PHPBB', 'PhpBB');
define('CMS_VBULLETIN', 'vBulletin');
define('CMS_SHOPSCRIPT', 'PHP ShopScript Premium');

define('CMS_VERSION_UNDEFINED', '0.0');

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class CmsVersionDetector {
    private $root_path;
    private $versions;
    private $types;
    
    public function __construct($root_path = '.') {
        $this->root_path = $root_path;
        $this->versions  = array();
        $this->types     = array();
        
        $version = '';
        
        $dir_list   = $this->getDirList($root_path);
        $dir_list[] = $root_path;
        
        foreach ($dir_list as $dir) {
            if ($this->checkBitrix($dir, $version)) {
                $this->addCms(CMS_BITRIX, $version);
            }
            
            if ($this->checkWordpress($dir, $version)) {
                $this->addCms(CMS_WORDPRESS, $version);
            }
            
            if ($this->checkJoomla($dir, $version)) {
                $this->addCms(CMS_JOOMLA, $version);
            }
            
            if ($this->checkDle($dir, $version)) {
                $this->addCms(CMS_DLE, $version);
            }
            
            if ($this->checkIpb($dir, $version)) {
                $this->addCms(CMS_IPB, $version);
            }
            
            if ($this->checkWebAsyst($dir, $version)) {
                $this->addCms(CMS_WEBASYST, $version);
            }
            
            if ($this->checkOsCommerce($dir, $version)) {
                $this->addCms(CMS_OSCOMMERCE, $version);
            }
            
            if ($this->checkDrupal($dir, $version)) {
                $this->addCms(CMS_DRUPAL, $version);
            }
            
            if ($this->checkMODX($dir, $version)) {
                $this->addCms(CMS_MODX, $version);
            }
            
            if ($this->checkInstantCms($dir, $version)) {
                $this->addCms(CMS_INSTANTCMS, $version);
            }
            
            if ($this->checkPhpBb($dir, $version)) {
                $this->addCms(CMS_PHPBB, $version);
            }
            
            if ($this->checkVBulletin($dir, $version)) {
                $this->addCms(CMS_VBULLETIN, $version);
            }
            
            if ($this->checkPhpShopScript($dir, $version)) {
                $this->addCms(CMS_SHOPSCRIPT, $version);
            }
            
        }
    }
    
    function getDirList($target) {
        $remove      = array(
            '.',
            '..'
        );
        $directories = array_diff(scandir($target), $remove);
        
        $res = array();
        
        foreach ($directories as $value) {
            if (is_dir($target . '/' . $value)) {
                $res[] = $target . '/' . $value;
            }
        }
        
        return $res;
    }
    
    function isCms($name, $version) {
        for ($i = 0; $i < count($this->types); $i++) {
            if ((strpos($this->types[$i], $name) !== false) && (strpos($this->versions[$i], $version) !== false)) {
                return true;
            }
        }
        
        return false;
    }
    
    function getCmsList() {
        return $this->types;
    }
    
    function getCmsVersions() {
        return $this->versions;
    }
    
    function getCmsNumber() {
        return count($this->types);
    }
    
    function getCmsName($index = 0) {
        return $this->types[$index];
    }
    
    function getCmsVersion($index = 0) {
        return $this->versions[$index];
    }
    
    private function addCms($type, $version) {
        $this->types[]    = $type;
        $this->versions[] = $version;
    }
    
    private function checkBitrix($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/bitrix')) {
            $res = true;
            
            $tmp_content = @file_get_contents($this->root_path . '/bitrix/modules/main/classes/general/version.php');
            if (preg_match('|define\("SM_VERSION","(.+?)"\)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkWordpress($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/wp-admin')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/wp-includes/version.php');
            if (preg_match('|\$wp_version\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
        }
        
        return $res;
    }
    
    private function checkJoomla($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/libraries/joomla')) {
            $res = true;
            
            // for 1.5.x
            $tmp_content = @file_get_contents($dir . '/libraries/joomla/version.php');
            if (preg_match('|var\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|var\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
            // for 1.7.x
            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|public\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|public\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
            
            // for 2.5.x and 3.x 
            $tmp_content = @file_get_contents($dir . '/libraries/cms/version/version.php');
            
            if (preg_match('|const\s+RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|const\s+DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
        }
        
        return $res;
    }
    
    private function checkDle($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/engine/engine.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/engine/data/config.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
            $tmp_content = @file_get_contents($dir . '/install.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkIpb($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/ips_kernel')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/ips_kernel/class_xml.php');
            if (preg_match('|IP.Board\s+v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkWebAsyst($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/wbs/installer')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/license.txt');
            if (preg_match('|v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkOsCommerce($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/includes/version.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkDrupal($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/sites/all')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/CHANGELOG.txt');
            if (preg_match('|Drupal\s+([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        if (file_exists($dir . '/core/lib/Drupal.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/core/lib/Drupal.php');
            if (preg_match('|VERSION\s*=\s*\'(\d+\.\d+\.\d+)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        if (file_exists($dir . 'modules/system/system.info')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . 'modules/system/system.info');
            if (preg_match('|version\s*=\s*"\d+\.\d+"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkMODX($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/manager/assets')) {
            $res = true;
            
            // no way to pick up version
        }
        
        return $res;
    }
    
    private function checkInstantCms($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/plugins/p_usertab')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/index.php');
            if (preg_match('|InstantCMS\s+v([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkPhpBb($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/includes/acp')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/config.php');
            if (preg_match('|phpBB\s+([0-9\.x]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkVBulletin($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        if (file_exists($dir . '/core/includes/md5_sums_vbulletin.php')) {
            $res = true;
            require_once($dir . '/core/includes/md5_sums_vbulletin.php');
            $version = $md5_sum_versions['vb5_connect'];
        } else if (file_exists($dir . '/includes/md5_sums_vbulletin.php')) {
            $res = true;
            require_once($dir . '/includes/md5_sums_vbulletin.php');
            $version = $md5_sum_versions['vbulletin'];
        }
        return $res;
    }
    
    private function checkPhpShopScript($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/install/consts.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/install/consts.php');
            if (preg_match('|STRING_VERSION\',\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
}

/**
 * Print file
 */
function printFile() {
    die("Not Supported");
 
    $l_FileName = $_GET['fn'];
    $l_CRC      = isset($_GET['c']) ? (int) $_GET['c'] : 0;
    $l_Content  = file_get_contents($l_FileName);
    $l_FileCRC  = realCRC($l_Content);
    if ($l_FileCRC != $l_CRC) {
        echo 'Доступ запрещен.';
        exit;
    }
    
    echo '<pre>' . htmlspecialchars($l_Content) . '</pre>';
}

/**
 *
 */
function realCRC($str_in, $full = false) {
    $in = crc32($full ? normal($str_in) : $str_in);
    return ($in > CRC32_LIMIT) ? ($in - CRC32_DIFF) : $in;
}


/**
 * Determine php script is called from the command line interface
 * @return bool
 */
function isCli() {
    return php_sapi_name() == 'cli';
}

function myCheckSum($str) {
    return hash('crc32b', $str);
}

function generatePassword($length = 9) {
    
    // start with a blank password
    $password = "";
    
    // define possible characters - any character in this string can be
    // picked for use in the password, so if you want to put vowels back in
    // or add special characters such as exclamation marks, this is where
    // you should do it
    $possible = "2346789bcdfghjkmnpqrtvwxyzBCDFGHJKLMNPQRTVWXYZ";
    
    // we refer to the length of $possible a few times, so let's grab it now
    $maxlength = strlen($possible);
    
    // check for length overflow and truncate if necessary
    if ($length > $maxlength) {
        $length = $maxlength;
    }
    
    // set up a counter for how many characters are in the password so far
    $i = 0;
    
    // add random characters to $password until $length is reached
    while ($i < $length) {
        
        // pick a random character from the possible ones
        $char = substr($possible, mt_rand(0, $maxlength - 1), 1);
        
        // have we already used this character in $password?
        if (!strstr($password, $char)) {
            // no, so it's OK to add it onto the end of whatever we've already got...
            $password .= $char;
            // ... and increase the counter by one
            $i++;
        }
        
    }
    
    // done!
    return $password;
    
}

/**
 * Print to console
 * @param mixed $text
 * @param bool $add_lb Add line break
 * @return void
 */
function stdOut($text, $add_lb = true) {
    if (!isCli())
        return;
    
    if (is_bool($text)) {
        $text = $text ? 'true' : 'false';
    } else if (is_null($text)) {
        $text = 'null';
    }
    if (!is_scalar($text)) {
        $text = print_r($text, true);
    }
    
    if ((!BOOL_RESULT) && (!JSON_STDOUT)) {
        @fwrite(STDOUT, $text . ($add_lb ? "\n" : ''));
    }
}

/**
 * Print progress
 * @param int $num Current file
 */
function printProgress($num, &$par_File) {
    global $g_CriticalPHP, $g_Base64, $g_Phishing, $g_CriticalJS, $g_Iframer, $g_UpdatedJsonLog, $g_AddPrefix, $g_NoPrefix;
    
    $total_files  = $GLOBALS['g_FoundTotalFiles'];
    $elapsed_time = microtime(true) - START_TIME;
    $percent      = number_format($total_files ? $num * 100 / $total_files : 0, 1);
    $stat         = '';
    if ($elapsed_time >= 1) {
        $elapsed_seconds = round($elapsed_time, 0);
        $fs              = floor($num / $elapsed_seconds);
        $left_files      = $total_files - $num;
        if ($fs > 0) {
            $left_time = ($left_files / $fs); //ceil($left_files / $fs);
            $stat      = ' [Avg: ' . round($fs, 2) . ' files/s' . ($left_time > 0 ? ' Left: ' . seconds2Human($left_time) : '') . '] [Mlw:' . (count($g_CriticalPHP) + count($g_Base64)) . '|' . (count($g_CriticalJS) + count($g_Iframer) + count($g_Phishing)) . ']';
        }
    }
    
    $l_FN = $g_AddPrefix . str_replace($g_NoPrefix, '', $par_File);
    $l_FN = substr($par_File, -60);
    
    $text = "$percent% [$l_FN] $num of {$total_files}. " . $stat;
    $text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
    stdOut(str_repeat(chr(8), 160) . $text, false);
    
    
    $data = array(
        'self' => __FILE__,
        'started' => AIBOLIT_START_TIME,
        'updated' => time(),
        'progress' => $percent,
        'time_elapsed' => $elapsed_seconds,
        'time_left' => round($left_time),
        'files_left' => $left_files,
        'files_total' => $total_files,
        'current_file' => substr($g_AddPrefix . str_replace($g_NoPrefix, '', $par_File), -160)
    );
    
    if (function_exists('aibolit_onProgressUpdate')) {
        aibolit_onProgressUpdate($data);
    }
    
    if (defined('PROGRESS_LOG_FILE') && (time() - $g_UpdatedJsonLog > 1)) {
        if (function_exists('json_encode')) {
            file_put_contents(PROGRESS_LOG_FILE, json_encode($data));
        } else {
            file_put_contents(PROGRESS_LOG_FILE, serialize($data));
        }
        
        $g_UpdatedJsonLog = time();
    }
}

/**
 * Seconds to human readable
 * @param int $seconds
 * @return string
 */
function seconds2Human($seconds) {
    $r        = '';
    $_seconds = floor($seconds);
    $ms       = $seconds - $_seconds;
    $seconds  = $_seconds;
    if ($hours = floor($seconds / 3600)) {
        $r .= $hours . (isCli() ? ' h ' : ' час ');
        $seconds = $seconds % 3600;
    }
    
    if ($minutes = floor($seconds / 60)) {
        $r .= $minutes . (isCli() ? ' m ' : ' мин ');
        $seconds = $seconds % 60;
    }
    
    if ($minutes < 3)
        $r .= ' ' . $seconds + ($ms > 0 ? round($ms) : 0) . (isCli() ? ' s' : ' сек');
    
    return $r;
}

if (isCli()) {
    
    $cli_options = array(
        'y' => 'deobfuscate',
        'c:' => 'avdb:',
        'm:' => 'memory:',
        's:' => 'size:',
        'a' => 'all',
        'd:' => 'delay:',
        'l:' => 'list:',
        'r:' => 'report:',
        'f' => 'fast',
        'j:' => 'file:',
        'p:' => 'path:',
        'q' => 'quite',
        'e:' => 'cms:',
        'x:' => 'mode:',
        'k:' => 'skip:',
        'i:' => 'idb:',
        'n' => 'sc',
        'o:' => 'json_report:',
        't:' => 'php_report:',
        'z:' => 'progress:',
        'g:' => 'handler:',
        'b' => 'smart',
        'u:' => 'username:',
        'h' => 'help'
    );
    
    $cli_longopts = array(
        'deobfuscate',
        'avdb:',
        'cmd:',
        'noprefix:',
        'addprefix:',
        'scan:',
        'one-pass',
        'smart',
        'quarantine',
        'with-2check',
        'skip-cache',
        'username:',
        'imake',
        'icheck',
        'no-html',
        'json-stdout', 
        'listing:'
    );
    
    $cli_longopts = array_merge($cli_longopts, array_values($cli_options));
    
    $options = getopt(implode('', array_keys($cli_options)), $cli_longopts);
    
    if (isset($options['h']) OR isset($options['help'])) {
        $memory_limit = ini_get('memory_limit');
        echo <<<HELP
Revisium AI-Bolit - an Intelligent Malware File Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS] [PATH]
Current default path is: {$defaults['path']}

  -j, --file=FILE      		Full path to single file to check
  -p, --path=PATH      		Directory path to scan, by default the file directory is used
                       		Current path: {$defaults['path']}
  -p, --listing=FILE      	Scan files from the listing. E.g. --listing=/tmp/myfilelist.txt
                                Use --listing=stdin to get listing from stdin stream
  -x, --mode=INT       		Set scan mode. 0 - for basic, 1 - for expert and 2 for paranoic.
  -k, --skip=jpg,...   		Skip specific extensions. E.g. --skip=jpg,gif,png,xls,pdf
      --scan=php,...   		Scan only specific extensions. E.g. --scan=php,htaccess,js

  -r, --report=PATH
  -o, --json_report=FILE	Full path to create json-file with a list of found malware
  -l, --list=FILE      		Full path to create plain text file with a list of found malware
      --no-html                 Disable HTML report

      --smart                   Enable smart mode (skip cache files and optimize scanning)
  -m, --memory=SIZE    		Maximum amount of memory a script may consume. Current value: $memory_limit
                       		Can take shorthand byte values (1M, 1G...)
  -s, --size=SIZE      		Scan files are smaller than SIZE. 0 - All files. Current value: {$defaults['max_size_to_scan']}
  -d, --delay=INT      		Delay in milliseconds when scanning files to reduce load on the file system (Default: 1)
  -a, --all            		Scan all files (by default scan. js,. php,. html,. htaccess)
      --one-pass       		Do not calculate remaining time
      --quarantine     		Archive all malware from report
      --with-2check    		Create or use AI-BOLIT-DOUBLECHECK.php file
      --imake
      --icheck
      --idb=file	   	Integrity Check database file

  -z, --progress=FILE  		Runtime progress of scanning, saved to the file, full path required. 
  -u, --username=<username>  	Run scanner with specific user id and group id, e.g. --username=www-data
  -g, --hander=FILE    		External php handler for different events, full path to php file required.
      --cmd="command [args...]"	Run command after scanning

      --help           		Display this help and exit

* Mandatory arguments listed below are required for both full and short way of usage.

HELP;
        exit;
    }
    
    $l_FastCli = false;

    if ((isset($options['memory']) AND !empty($options['memory']) AND ($memory = $options['memory'])) OR (isset($options['m']) AND !empty($options['m']) AND ($memory = $options['m']))) {
        $memory = getBytes($memory);
        if ($memory > 0) {
            $defaults['memory_limit'] = $memory;
            ini_set('memory_limit', $memory);
        }
    }
    
    
    $avdb = '';
    if ((isset($options['avdb']) AND !empty($options['avdb']) AND ($avdb = $options['avdb'])) OR (isset($options['c']) AND !empty($options['c']) AND ($avdb = $options['c']))) {
        if (file_exists($avdb)) {
            $defaults['avdb'] = $avdb;
        }
    }
    
    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)) {
        define('SCAN_FILE', $file);
    }
    
    
    if (isset($options['deobfuscate']) OR isset($options['y'])) {
        define('AI_DEOBFUSCATE', true);
    }
    
    if ((isset($options['list']) AND !empty($options['list']) AND ($file = $options['list']) !== false) OR (isset($options['l']) AND !empty($options['l']) AND ($file = $options['l']) !== false)) {
        
        define('PLAIN_FILE', $file);
    }
    
    if ((isset($options['listing']) AND !empty($options['listing']) AND ($listing = $options['listing']) !== false)) {
        
        if (file_exists($listing) && is_file($listing) && is_readable($listing)) {
            define('LISTING_FILE', $listing);
        }

        if ($listing == 'stdin') {
            define('LISTING_FILE', $listing);
        }
    }
    
    if ((isset($options['json_report']) AND !empty($options['json_report']) AND ($file = $options['json_report']) !== false) OR (isset($options['o']) AND !empty($options['o']) AND ($file = $options['o']) !== false)) {
        define('JSON_FILE', $file);

        if (!function_exists('json_encode')) {
           die('json_encode function is not available. Enable json extension in php.ini');
        }
    }
    
    if ((isset($options['php_report']) AND !empty($options['php_report']) AND ($file = $options['php_report']) !== false) OR (isset($options['t']) AND !empty($options['t']) AND ($file = $options['t']) !== false)) {
        define('PHP_FILE', $file);
    }
    
    if (isset($options['smart']) OR isset($options['b'])) {
        define('SMART_SCAN', 1);
    }
    
    if ((isset($options['handler']) AND !empty($options['handler']) AND ($file = $options['handler']) !== false) OR (isset($options['g']) AND !empty($options['g']) AND ($file = $options['g']) !== false)) {
        if (file_exists($file)) {
            define('AIBOLIT_EXTERNAL_HANDLER', $file);
        }
    }
    
    if ((isset($options['progress']) AND !empty($options['progress']) AND ($file = $options['progress']) !== false) OR (isset($options['z']) AND !empty($options['z']) AND ($file = $options['z']) !== false)) {
        define('PROGRESS_LOG_FILE', $file);
    }
    
    if ((isset($options['size']) AND !empty($options['size']) AND ($size = $options['size']) !== false) OR (isset($options['s']) AND !empty($options['s']) AND ($size = $options['s']) !== false)) {
        $size                         = getBytes($size);
        $defaults['max_size_to_scan'] = $size > 0 ? $size : 0;
    }
    
    if ((isset($options['username']) AND !empty($options['username']) AND ($username = $options['username']) !== false) OR (isset($options['u']) AND !empty($options['u']) AND ($username = $options['u']) !== false)) {
        
        if (!empty($username) && ($info = posix_getpwnam($username)) !== false) {
            posix_setgid($info['gid']);
            posix_setuid($info['uid']);
            $defaults['userid']  = $info['uid'];
            $defaults['groupid'] = $info['gid'];
        } else {
            echo ('Invalid username');
            exit(-1);
        }
    }
    
    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false) AND (isset($options['q']))) {
        $BOOL_RESULT = true;
    }
    
    if (isset($options['json-stdout'])) {
       define('JSON_STDOUT', true);  
    } else {
       define('JSON_STDOUT', false);  
    }

    if (isset($options['f'])) {
        $l_FastCli = true;
    }
    
    if (isset($options['q']) || isset($options['quite'])) {
        $BOOL_RESULT = true;
    }
    
    if (isset($options['x'])) {
        define('AI_EXPERT', $options['x']);
    } else if (isset($options['mode'])) {
        define('AI_EXPERT', $options['mode']);
    } else {
        define('AI_EXPERT', AI_EXPERT_MODE);
    }
    
    if (AI_EXPERT < 2) {
        $g_SpecificExt              = true;
        $defaults['scan_all_files'] = false;
    } else {
        $defaults['scan_all_files'] = true;
    }
    
    define('BOOL_RESULT', $BOOL_RESULT);
    
    if ((isset($options['delay']) AND !empty($options['delay']) AND ($delay = $options['delay']) !== false) OR (isset($options['d']) AND !empty($options['d']) AND ($delay = $options['d']) !== false)) {
        $delay = (int) $delay;
        if (!($delay < 0)) {
            $defaults['scan_delay'] = $delay;
        }
    }
    
    if ((isset($options['skip']) AND !empty($options['skip']) AND ($ext_list = $options['skip']) !== false) OR (isset($options['k']) AND !empty($options['k']) AND ($ext_list = $options['k']) !== false)) {
        $defaults['skip_ext'] = $ext_list;
    }
    
    if (isset($options['n']) OR isset($options['skip-cache'])) {
        $defaults['skip_cache'] = true;
    }
    
    if (isset($options['scan'])) {
        $ext_list = strtolower(trim($options['scan'], " ,\t\n\r\0\x0B"));
        if ($ext_list != '') {
            $l_FastCli        = true;
            $g_SensitiveFiles = explode(",", $ext_list);
            for ($i = 0; $i < count($g_SensitiveFiles); $i++) {
                if ($g_SensitiveFiles[$i] == '.') {
                    $g_SensitiveFiles[$i] = '';
                }
            }
            
            $g_SpecificExt = true;
        }
    }
    
    
    if (isset($options['all']) OR isset($options['a'])) {
        $defaults['scan_all_files'] = true;
        $g_SpecificExt              = false;
    }
    
    if (isset($options['cms'])) {
        define('CMS', $options['cms']);
    } else if (isset($options['e'])) {
        define('CMS', $options['e']);
    }
    
    
    if (!defined('SMART_SCAN')) {
        define('SMART_SCAN', 1);
    }
    
    if (!defined('AI_DEOBFUSCATE')) {
        define('AI_DEOBFUSCATE', false);
    }
    
    
    $l_SpecifiedPath = false;
    if ((isset($options['path']) AND !empty($options['path']) AND ($path = $options['path']) !== false) OR (isset($options['p']) AND !empty($options['p']) AND ($path = $options['p']) !== false)) {
        $defaults['path'] = $path;
        $l_SpecifiedPath  = true;
    }
    
    if (isset($options['noprefix']) AND !empty($options['noprefix']) AND ($g_NoPrefix = $options['noprefix']) !== false) {
    } else {
        $g_NoPrefix = '';
    }
    
    if (isset($options['addprefix']) AND !empty($options['addprefix']) AND ($g_AddPrefix = $options['addprefix']) !== false) {
    } else {
        $g_AddPrefix = '';
    }
    
    
    
    $l_SuffixReport = str_replace('/var/www', '', $defaults['path']);
    $l_SuffixReport = str_replace('/home', '', $l_SuffixReport);
    $l_SuffixReport = preg_replace('#[/\\\.\s]#', '_', $l_SuffixReport);
    $l_SuffixReport .= "-" . rand(1, 999999);
    
    if ((isset($options['report']) AND ($report = $options['report']) !== false) OR (isset($options['r']) AND ($report = $options['r']) !== false)) {
        $report = str_replace('@PATH@', $l_SuffixReport, $report);
        $report = str_replace('@RND@', rand(1, 999999), $report);
        $report = str_replace('@DATE@', date('d-m-Y-h-i'), $report);
        define('REPORT', $report);
        define('NEED_REPORT', true);
    }
    
    if (isset($options['no-html'])) {
        define('REPORT', 'no@email.com');
    }
    
    if ((isset($options['idb']) AND ($ireport = $options['idb']) !== false)) {
        $ireport = str_replace('@PATH@', $l_SuffixReport, $ireport);
        $ireport = str_replace('@RND@', rand(1, 999999), $ireport);
        $ireport = str_replace('@DATE@', date('d-m-Y-h-i'), $ireport);
        define('INTEGRITY_DB_FILE', $ireport);
    }
    
    
    defined('REPORT') OR define('REPORT', 'AI-BOLIT-REPORT-' . $l_SuffixReport . '-' . date('d-m-Y_H-i') . '.html');
    
    defined('INTEGRITY_DB_FILE') OR define('INTEGRITY_DB_FILE', 'AINTEGRITY-' . $l_SuffixReport . '-' . date('d-m-Y_H-i'));
    
    $last_arg = max(1, sizeof($_SERVER['argv']) - 1);
    if (isset($_SERVER['argv'][$last_arg])) {
        $path = $_SERVER['argv'][$last_arg];
        if (substr($path, 0, 1) != '-' AND (substr($_SERVER['argv'][$last_arg - 1], 0, 1) != '-' OR array_key_exists(substr($_SERVER['argv'][$last_arg - 1], -1), $cli_options))) {
            $defaults['path'] = $path;
        }
    }    
    
    define('ONE_PASS', isset($options['one-pass']));
    
    define('IMAKE', isset($options['imake']));
    define('ICHECK', isset($options['icheck']));
    
    if (IMAKE && ICHECK)
        die('One of the following options must be used --imake or --icheck.');
    
} else {
    define('AI_EXPERT', AI_EXPERT_MODE);
    define('ONE_PASS', true);
}


if (isset($defaults['avdb']) && file_exists($defaults['avdb'])) {
    $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($defaults['avdb'])))))));
    
    $g_DBShe       = explode("\n", base64_decode($avdb[0]));
    $gX_DBShe      = explode("\n", base64_decode($avdb[1]));
    $g_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
    $gX_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
    $gXX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
    $g_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
    $g_AdwareSig   = explode("\n", base64_decode($avdb[6]));
    $g_PhishingSig = explode("\n", base64_decode($avdb[7]));
    $g_JSVirSig    = explode("\n", base64_decode($avdb[8]));
    $gX_JSVirSig   = explode("\n", base64_decode($avdb[9]));
    $g_SusDB       = explode("\n", base64_decode($avdb[10]));
    $g_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
    $g_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
    $g_Mnemo    = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15]))));
    
    if (count($g_DBShe) <= 1) {
        $g_DBShe = array();
    }
    
    if (count($gX_DBShe) <= 1) {
        $gX_DBShe = array();
    }
    
    if (count($g_FlexDBShe) <= 1) {
        $g_FlexDBShe = array();
    }
    
    if (count($gX_FlexDBShe) <= 1) {
        $gX_FlexDBShe = array();
    }
    
    if (count($gXX_FlexDBShe) <= 1) {
        $gXX_FlexDBShe = array();
    }
    
    if (count($g_ExceptFlex) <= 1) {
        $g_ExceptFlex = array();
    }
    
    if (count($g_AdwareSig) <= 1) {
        $g_AdwareSig = array();
    }
    
    if (count($g_PhishingSig) <= 1) {
        $g_PhishingSig = array();
    }
    
    if (count($gX_JSVirSig) <= 1) {
        $gX_JSVirSig = array();
    }
    
    if (count($g_JSVirSig) <= 1) {
        $g_JSVirSig = array();
    }
    
    if (count($g_SusDB) <= 1) {
        $g_SusDB = array();
    }
    
    if (count($g_SusDBPrio) <= 1) {
        $g_SusDBPrio = array();
    }
    
    stdOut('Loaded external signatures from ' . $defaults['avdb']);
}

// use only basic signature subset
if (AI_EXPERT < 2) {
    $gX_FlexDBShe  = array();
    $gXX_FlexDBShe = array();
    $gX_JSVirSig   = array();
}

if (isset($defaults['userid'])) {
    stdOut('Running from ' . $defaults['userid'] . ':' . $defaults['groupid']);
}

stdOut('Malware signatures: ' . (count($g_JSVirSig) + count($gX_JSVirSig) + count($g_DBShe) + count($gX_DBShe) + count($gX_DBShe) + count($g_FlexDBShe) + count($gX_FlexDBShe) + count($gXX_FlexDBShe)));

if ($g_SpecificExt) {
    stdOut("Scan specific extensions: " . implode(',', $g_SensitiveFiles));
}

if (!DEBUG_PERFORMANCE) {
    OptimizeSignatures();
} else {
    stdOut("Debug Performance Scan");
}

$g_DBShe  = array_map('strtolower', $g_DBShe);
$gX_DBShe = array_map('strtolower', $gX_DBShe);

if (!defined('PLAIN_FILE')) {
    define('PLAIN_FILE', '');
}

// Init
define('MAX_ALLOWED_PHP_HTML_IN_DIR', 600);
define('BASE64_LENGTH', 69);
define('MAX_PREVIEW_LEN', 120);
define('MAX_EXT_LINKS', 1001);

if (defined('AIBOLIT_EXTERNAL_HANDLER')) {
    include_once(AIBOLIT_EXTERNAL_HANDLER);
    stdOut("\nLoaded external handler: " . AIBOLIT_EXTERNAL_HANDLER . "\n");
    if (function_exists("aibolit_onStart")) {
        aibolit_onStart();
    }
}

// Perform full scan when running from command line
if (isset($_GET['full'])) {
    $defaults['scan_all_files'] = 1;
}

if ($l_FastCli) {
    $defaults['scan_all_files'] = 0;
}

if (!isCli()) {
    define('ICHECK', isset($_GET['icheck']));
    define('IMAKE', isset($_GET['imake']));
    
    define('INTEGRITY_DB_FILE', 'ai-integrity-db');
}

define('SCAN_ALL_FILES', (bool) $defaults['scan_all_files']);
define('SCAN_DELAY', (int) $defaults['scan_delay']);
define('MAX_SIZE_TO_SCAN', getBytes($defaults['max_size_to_scan']));

if ($defaults['memory_limit'] AND ($defaults['memory_limit'] = getBytes($defaults['memory_limit'])) > 0) {
    ini_set('memory_limit', $defaults['memory_limit']);
    stdOut("Changed memory limit to " . $defaults['memory_limit']);
}

define('ROOT_PATH', realpath($defaults['path']));

if (!ROOT_PATH) {
    if (isCli()) {
        die(stdOut("Directory '{$defaults['path']}' not found!"));
    }
} elseif (!is_readable(ROOT_PATH)) {
    if (isCli()) {
        die2(stdOut("Cannot read directory '" . ROOT_PATH . "'!"));
    }
}

define('CURRENT_DIR', getcwd());
chdir(ROOT_PATH);

if (isCli() AND REPORT !== '' AND !getEmails(REPORT)) {
    $report      = str_replace('\\', '/', REPORT);
    $abs         = strpos($report, '/') === 0 ? DIR_SEPARATOR : '';
    $report      = array_values(array_filter(explode('/', $report)));
    $report_file = array_pop($report);
    $report_path = realpath($abs . implode(DIR_SEPARATOR, $report));
    
    define('REPORT_FILE', $report_file);
    define('REPORT_PATH', $report_path);
    
    if (REPORT_FILE AND REPORT_PATH AND is_file(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE)) {
        @unlink(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE);
    }
}

if (defined('REPORT_PATH')) {
    $l_ReportDirName = REPORT_PATH;
}

define('QUEUE_FILENAME', ($l_ReportDirName != '' ? $l_ReportDirName . '/' : '') . 'AI-BOLIT-QUEUE-' . md5($defaults['path']) . '-' . rand(1000, 9999) . '.txt');

if (function_exists('phpinfo')) {
    ob_start();
    phpinfo();
    $l_PhpInfo = ob_get_contents();
    ob_end_clean();
    
    $l_PhpInfo = str_replace('border: 1px', '', $l_PhpInfo);
    preg_match('|<body>(.*)</body>|smi', $l_PhpInfo, $l_PhpInfoBody);
}

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MODE@@", AI_EXPERT . '/' . SMART_SCAN, $l_Template);

if (AI_EXPERT == 0) {
    $l_Result .= '<div class="rep">' . AI_STR_057 . '</div>';
} else {
}

$l_Template = str_replace('@@HEAD_TITLE@@', AI_STR_051 . $g_AddPrefix . str_replace($g_NoPrefix, '', ROOT_PATH), $l_Template);

define('QCR_INDEX_FILENAME', 'fn');
define('QCR_INDEX_TYPE', 'type');
define('QCR_INDEX_WRITABLE', 'wr');
define('QCR_SVALUE_FILE', '1');
define('QCR_SVALUE_FOLDER', '0');

/**
 * Extract emails from the string
 * @param string $email
 * @return array of strings with emails or false on error
 */
function getEmails($email) {
    $email = preg_split('#[,\s;]#', $email, -1, PREG_SPLIT_NO_EMPTY);
    $r     = array();
    for ($i = 0, $size = sizeof($email); $i < $size; $i++) {
        if (function_exists('filter_var')) {
            if (filter_var($email[$i], FILTER_VALIDATE_EMAIL)) {
                $r[] = $email[$i];
            }
        } else {
            // for PHP4
            if (strpos($email[$i], '@') !== false) {
                $r[] = $email[$i];
            }
        }
    }
    return empty($r) ? false : $r;
}

/**
 * Get bytes from shorthand byte values (1M, 1G...)
 * @param int|string $val
 * @return int
 */
function getBytes($val) {
    $val  = trim($val);
    $last = strtolower($val{strlen($val) - 1});
    switch ($last) {
        case 't':
            $val *= 1024;
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }
    return intval($val);
}

/**
 * Format bytes to human readable
 * @param int $bites
 * @return string
 */
function bytes2Human($bites) {
    if ($bites < 1024) {
        return $bites . ' b';
    } elseif (($kb = $bites / 1024) < 1024) {
        return number_format($kb, 2) . ' Kb';
    } elseif (($mb = $kb / 1024) < 1024) {
        return number_format($mb, 2) . ' Mb';
    } elseif (($gb = $mb / 1024) < 1024) {
        return number_format($gb, 2) . ' Gb';
    } else {
        return number_format($gb / 1024, 2) . 'Tb';
    }
}

///////////////////////////////////////////////////////////////////////////
function needIgnore($par_FN, $par_CRC) {
    global $g_IgnoreList;
    
    for ($i = 0; $i < count($g_IgnoreList); $i++) {
        if (strpos($par_FN, $g_IgnoreList[$i][0]) !== false) {
            if ($par_CRC == $g_IgnoreList[$i][1]) {
                return true;
            }
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function makeSafeFn($par_Str, $replace_path = false) {
    global $g_AddPrefix, $g_NoPrefix;
    if ($replace_path) {
        $lines = explode("\n", $par_Str);
        array_walk($lines, function(&$n) {
            global $g_AddPrefix, $g_NoPrefix;
            $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
        });
        
        $par_Str = implode("\n", $lines);
    }
    
    return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
}

function replacePathArray($par_Arr) {
    global $g_AddPrefix, $g_NoPrefix;
    array_walk($par_Arr, function(&$n) {
        global $g_AddPrefix, $g_NoPrefix;
        $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
    });
    
    return $par_Arr;
}

///////////////////////////////////////////////////////////////////////////
function getRawJsonVuln($par_List) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    $results = array();
    $l_Src   = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;',
        '<' . '?php.'
    );
    $l_Dst   = array(
        '"',
        '<',
        '>',
        '&',
        '\'',
        '<' . '?php '
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        $l_Pos      = $par_List[$i]['ndx'];
        $res['fn']  = convertToUTF8($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]));
        $res['sig'] = $par_List[$i]['id'];
        
        $res['ct']    = $g_Structure['c'][$l_Pos];
        $res['mt']    = $g_Structure['m'][$l_Pos];
        $res['sz']    = $g_Structure['s'][$l_Pos];
        $res['sigid'] = 'vuln_' . md5($g_Structure['n'][$l_Pos] . $par_List[$i]['id']);
        
        $results[] = $res;
    }
    
    return $results;
}

///////////////////////////////////////////////////////////////////////////
function getRawJson($par_List, $par_Details = null, $par_SigId = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix, $g_Mnemo;
    $results = array();
    $l_Src   = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;',
        '<' . '?php.'
    );
    $l_Dst   = array(
        '"',
        '<',
        '>',
        '&',
        '\'',
        '<' . '?php '
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        if ($par_SigId != null) {
            $l_SigId = 'id_' . $par_SigId[$i];
        } else {
            $l_SigId = 'id_n' . rand(1000000, 9000000);
        }
                
        $l_Pos     = $par_List[$i];
        $res['fn'] = convertToUTF8($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]));
        if ($par_Details != null) {
            $res['sig'] = preg_replace('|(L\d+).+__AI_MARKER__|smi', '[$1]: ...', $par_Details[$i]);
            $res['sig'] = preg_replace('/[^\x20-\x7F]/', '.', $res['sig']);
            $res['sig'] = preg_replace('/__AI_LINE1__(\d+)__AI_LINE2__/', '[$1] ', $res['sig']);
            $res['sig'] = preg_replace('/__AI_MARKER__/', ' @!!!>', $res['sig']);
            $res['sig'] = str_replace($l_Src, $l_Dst, $res['sig']);            
        }
        
        $res['sig'] = convertToUTF8($res['sig']);

        $res['ct']    = $g_Structure['c'][$l_Pos];
        $res['mt']    = $g_Structure['m'][$l_Pos];
        $res['sz']    = $g_Structure['s'][$l_Pos];
        $res['hash']  = $g_Structure['crc'][$l_Pos];
        $res['sigid'] = $l_SigId;
        
        if (isset($par_SigId) && isset($g_Mnemo[$par_SigId[$i]])) {
           $res['sn'] = $g_Mnemo[$par_SigId[$i]]; 
        } else {
           $res['sn'] = ''; 
        }

        $results[] = $res;
    }
    
    return $results;
}

///////////////////////////////////////////////////////////////////////////
function printList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    
    $i = 0;
    
    if ($par_TableName == null) {
        $par_TableName = 'table_' . rand(1000000, 9000000);
    }
    
    $l_Result = '';
    $l_Result .= "<div class=\"flist\"><table cellspacing=1 cellpadding=4 border=0 id=\"" . $par_TableName . "\">";
    
    $l_Result .= "<thead><tr class=\"tbgh" . ($i % 2) . "\">";
    $l_Result .= "<th width=70%>" . AI_STR_004 . "</th>";
    $l_Result .= "<th>" . AI_STR_005 . "</th>";
    $l_Result .= "<th>" . AI_STR_006 . "</th>";
    $l_Result .= "<th width=90>" . AI_STR_007 . "</th>";
    $l_Result .= "<th width=0 class=\"hidd\">CRC32</th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    
    $l_Result .= "</tr></thead><tbody>";
    
    for ($i = 0; $i < count($par_List); $i++) {
        if ($par_SigId != null) {
            $l_SigId = 'id_' . $par_SigId[$i];
        } else {
            $l_SigId = 'id_z' . rand(1000000, 9000000);
        }
        
        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
                continue;
            }
        }
        
        $l_Creat = $g_Structure['c'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['c'][$l_Pos]) : '-';
        $l_Modif = $g_Structure['m'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['m'][$l_Pos]) : '-';
        $l_Size  = $g_Structure['s'][$l_Pos] > 0 ? bytes2Human($g_Structure['s'][$l_Pos]) : '-';
        
        if ($par_Details != null) {
            $l_WithMarker = preg_replace('|__AI_MARKER__|smi', '<span class="marker">&nbsp;</span>', $par_Details[$i]);
            $l_WithMarker = preg_replace('|__AI_LINE1__|smi', '<span class="line_no">', $l_WithMarker);
            $l_WithMarker = preg_replace('|__AI_LINE2__|smi', '</span>', $l_WithMarker);
            
            $l_Body = '<div class="details">';
            
            if ($par_SigId != null) {
                $l_Body .= '<a href="#" onclick="return hsig(\'' . $l_SigId . '\')">[x]</a> ';
            }
            
            $l_Body .= $l_WithMarker . '</div>';
        } else {
            $l_Body = '';
        }
        
        $l_Result .= '<tr class="tbg' . ($i % 2) . '" o="' . $l_SigId . '">';
        
        if (is_file($g_Structure['n'][$l_Pos])) {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos])) . '</a></div>' . $l_Body . '</td>';
        } else {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]])) . '</a></div></td>';
        }
        
        $l_Result .= '<td align=center><div class="ctd">' . $l_Creat . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Modif . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Size . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['crc'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . 'x' . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['m'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $l_SigId . '</div></td>';
        $l_Result .= '</tr>';
        
    }
    
    $l_Result .= "</tbody></table></div><div class=clear style=\"margin: 20px 0 0 0\"></div>";
    
    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function printPlainList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    
    $l_Result = "";
    
    $l_Src = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;'
    );
    $l_Dst = array(
        '"',
        '<',
        '>',
        '&',
        '\''
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
                continue;
            }
        }
        
        
        if ($par_Details != null) {
            
            $l_Body = preg_replace('|(L\d+).+__AI_MARKER__|smi', '$1: ...', $par_Details[$i]);
            $l_Body = preg_replace('/[^\x20-\x7F]/', '.', $l_Body);
            $l_Body = str_replace($l_Src, $l_Dst, $l_Body);
            
        } else {
            $l_Body = '';
        }
        
        if (is_file($g_Structure['n'][$l_Pos])) {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]) . "\t\t\t" . $l_Body . "\n";
        } else {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]]) . "\n";
        }
        
    }
    
    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function extractValue(&$par_Str, $par_Name) {
    if (preg_match('|<tr><td class="e">\s*' . $par_Name . '\s*</td><td class="v">(.+?)</td>|sm', $par_Str, $l_Result)) {
        return str_replace('no value', '', strip_tags($l_Result[1]));
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ExtractInfo($par_Str) {
    $l_PhpInfoSystem    = extractValue($par_Str, 'System');
    $l_PhpPHPAPI        = extractValue($par_Str, 'Server API');
    $l_AllowUrlFOpen    = extractValue($par_Str, 'allow_url_fopen');
    $l_AllowUrlInclude  = extractValue($par_Str, 'allow_url_include');
    $l_DisabledFunction = extractValue($par_Str, 'disable_functions');
    $l_DisplayErrors    = extractValue($par_Str, 'display_errors');
    $l_ErrorReporting   = extractValue($par_Str, 'error_reporting');
    $l_ExposePHP        = extractValue($par_Str, 'expose_php');
    $l_LogErrors        = extractValue($par_Str, 'log_errors');
    $l_MQGPC            = extractValue($par_Str, 'magic_quotes_gpc');
    $l_MQRT             = extractValue($par_Str, 'magic_quotes_runtime');
    $l_OpenBaseDir      = extractValue($par_Str, 'open_basedir');
    $l_RegisterGlobals  = extractValue($par_Str, 'register_globals');
    $l_SafeMode         = extractValue($par_Str, 'safe_mode');
        
    $l_DisabledFunction = ($l_DisabledFunction == '' ? '-?-' : $l_DisabledFunction);
    $l_OpenBaseDir      = ($l_OpenBaseDir == '' ? '-?-' : $l_OpenBaseDir);
    
    $l_Result = '<div class="title">' . AI_STR_008 . ': ' . phpversion() . '</div>';
    $l_Result .= 'System Version: <span class="php_ok">' . $l_PhpInfoSystem . '</span><br/>';
    $l_Result .= 'PHP API: <span class="php_ok">' . $l_PhpPHPAPI . '</span><br/>';
    $l_Result .= 'allow_url_fopen: <span class="php_' . ($l_AllowUrlFOpen == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlFOpen . '</span><br/>';
    $l_Result .= 'allow_url_include: <span class="php_' . ($l_AllowUrlInclude == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlInclude . '</span><br/>';
    $l_Result .= 'disable_functions: <span class="php_' . ($l_DisabledFunction == '-?-' ? 'bad' : 'ok') . '">' . $l_DisabledFunction . '</span><br/>';
    $l_Result .= 'display_errors: <span class="php_' . ($l_DisplayErrors == 'On' ? 'ok' : 'bad') . '">' . $l_DisplayErrors . '</span><br/>';
    $l_Result .= 'error_reporting: <span class="php_ok">' . $l_ErrorReporting . '</span><br/>';
    $l_Result .= 'expose_php: <span class="php_' . ($l_ExposePHP == 'On' ? 'bad' : 'ok') . '">' . $l_ExposePHP . '</span><br/>';
    $l_Result .= 'log_errors: <span class="php_' . ($l_LogErrors == 'On' ? 'ok' : 'bad') . '">' . $l_LogErrors . '</span><br/>';
    $l_Result .= 'magic_quotes_gpc: <span class="php_' . ($l_MQGPC == 'On' ? 'ok' : 'bad') . '">' . $l_MQGPC . '</span><br/>';
    $l_Result .= 'magic_quotes_runtime: <span class="php_' . ($l_MQRT == 'On' ? 'bad' : 'ok') . '">' . $l_MQRT . '</span><br/>';
    $l_Result .= 'register_globals: <span class="php_' . ($l_RegisterGlobals == 'On' ? 'bad' : 'ok') . '">' . $l_RegisterGlobals . '</span><br/>';
    $l_Result .= 'open_basedir: <span class="php_' . ($l_OpenBaseDir == '-?-' ? 'bad' : 'ok') . '">' . $l_OpenBaseDir . '</span><br/>';
    
    if (phpversion() < '5.3.0') {
        $l_Result .= 'safe_mode (PHP < 5.3.0): <span class="php_' . ($l_SafeMode == 'On' ? 'ok' : 'bad') . '">' . $l_SafeMode . '</span><br/>';
    }
    
    return $l_Result . '<p>';
}

///////////////////////////////////////////////////////////////////////////
function addSlash($dir) {
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
}

///////////////////////////////////////////////////////////////////////////
function QCR_Debug($par_Str = "") {
    if (!DEBUG_MODE) {
        return;
    }
    
    $l_MemInfo = ' ';
    if (function_exists('memory_get_usage')) {
        $l_MemInfo .= ' curmem=' . bytes2Human(memory_get_usage());
    }
    
    if (function_exists('memory_get_peak_usage')) {
        $l_MemInfo .= ' maxmem=' . bytes2Human(memory_get_peak_usage());
    }
    
    stdOut("\n" . date('H:i:s') . ': ' . $par_Str . $l_MemInfo . "\n");
}


///////////////////////////////////////////////////////////////////////////
function QCR_ScanDirectories($l_RootDir) {
    global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, $defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SensitiveFiles, $g_SuspiciousFiles, $g_ShortListExt, $l_SkipSample;
    
    static $l_Buffer = '';
    
    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $g_Counter - 1;
    
    $l_SkipSample = array();
    
    QCR_Debug('Scan ' . $l_RootDir);
    
    $l_QuotedSeparator = quotemeta(DIR_SEPARATOR);
    if ($l_DIRH = @opendir($l_RootDir)) {
        while (($l_FileName = readdir($l_DIRH)) !== false) {
            if ($l_FileName == '.' || $l_FileName == '..')
                continue;
            
            $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;
            
            $l_Type = filetype($l_FileName);
            if ($l_Type == "link") {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else if ($l_Type != "file" && $l_Type != "dir") {                
                continue;
            }
            
            $l_Ext   = strtolower(pathinfo($l_FileName, PATHINFO_EXTENSION));
            $l_IsDir = is_dir($l_FileName);
            
            if (in_array($l_Ext, $g_SuspiciousFiles)) {
            }
            
            // which files should be scanned
            $l_NeedToScan = SCAN_ALL_FILES || (in_array($l_Ext, $g_SensitiveFiles));
            
            if (in_array(strtolower($l_Ext), $g_IgnoredExt)) {
                $l_NeedToScan = false;
            }
            
            // if folder in ignore list
            $l_Skip = false;
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                    if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                        $l_SkipSample[] = $g_DirIgnoreList[$dr];
                    } else {
                        $l_Skip       = true;
                        $l_NeedToScan = false;
                    }
                }
            }
            
            
            if ($l_IsDir) {
                // skip on ignore
                if ($l_Skip) {
                    $g_SkippedFolders[] = $l_FileName;
                    continue;
                }
                
                $l_BaseName = basename($l_FileName);
                
                if (ONE_PASS) {
                    $g_Structure['n'][$g_Counter] = $l_FileName . DIR_SEPARATOR;
                } else {
                    $l_Buffer .= $l_FileName . DIR_SEPARATOR . "\n";
                }
                
                $l_DirCounter++;
                
                if ($l_DirCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                    $g_Doorway[]  = $l_SourceDirIndex;
                    $l_DirCounter = -655360;
                }
                
                $g_Counter++;
                $g_FoundTotalDirs++;
                
                QCR_ScanDirectories($l_FileName);
            } else {
                if ($l_NeedToScan) {
                    $g_FoundTotalFiles++;
                    if (in_array($l_Ext, $g_ShortListExt)) {
                        $l_DoorwayFilesCounter++;
                        
                        if ($l_DoorwayFilesCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                            $g_Doorway[]           = $l_SourceDirIndex;
                            $l_DoorwayFilesCounter = -655360;
                        }
                    }
                    
                    if (ONE_PASS) {
                        QCR_ScanFile($l_FileName, $g_Counter++);
                    } else {
                        $l_Buffer .= $l_FileName . "\n";
                    }
                    
                    $g_Counter++;
                }
            }
            
            if (strlen($l_Buffer) > 32000) {
                file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
                $l_Buffer = '';
            }
            
        }
        
        closedir($l_DIRH);
    }
    
    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }
    
}


///////////////////////////////////////////////////////////////////////////
function getFragment($par_Content, $par_Pos) {
//echo "\n *********** --------------------------------------------------------\n";

    $l_MaxChars = MAX_PREVIEW_LEN;

    $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

    $l_MaxLen   = strlen($par_Content);
    $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen);
    $l_MinPos   = max(0, $par_Pos - $l_MaxChars);
    
    $l_FoundStart = substr($par_Content, 0, $par_Pos);
    $l_FoundStart = str_replace("\r", '', $l_FoundStart);
    $l_LineNo     = strlen($l_FoundStart) - strlen(str_replace("\n", '', $l_FoundStart)) + 1;

//echo "\nMinPos=" . $l_MinPos . " Pos=" . $par_Pos . " l_RightPos=" . $l_RightPos . "\n";
//var_dump($par_Content);
//echo "\n-----------------------------------------------------\n";

                                                                                                                                                      
    $l_Res = '__AI_LINE1__' . $l_LineNo . "__AI_LINE2__  " . ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);
    
    $l_Res = makeSafeFn(UnwrapObfu($l_Res));

    $l_Res = str_replace('~', ' ', $l_Res);

    $l_Res = preg_replace('~[\s\t]+~', ' ', $l_Res);
      
    $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);
    
//echo "\nFinal:\n";
//var_dump($l_Res);
//echo "\n-----------------------------------------------------\n";
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function escapedHexToHex($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(hexdec($escaped[1]));
}
function escapedOctDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(octdec($escaped[1]));
}
function escapedDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr($escaped[1]);
}

///////////////////////////////////////////////////////////////////////////
if (!defined('T_ML_COMMENT')) {
    define('T_ML_COMMENT', T_COMMENT);
} else {
    define('T_DOC_COMMENT', T_ML_COMMENT);
}

function UnwrapObfu($par_Content) {
    $GLOBALS['g_EncObfu'] = 0;
    
    $search      = array(
        ' ;',
        ' =',
        ' ,',
        ' .',
        ' (',
        ' )',
        ' {',
        ' }',
        '; ',
        '= ',
        ', ',
        '. ',
        '( ',
        '( ',
        '{ ',
        '} ',
        ' !',
        ' >',
        ' <',
        ' _',
        '_ ',
        '< ',
        '> ',
        ' $',
        ' %',
        '% ',
        '# ',
        ' #',
        '^ ',
        ' ^',
        ' &',
        '& ',
        ' ?',
        '? '
    );
    $replace     = array(
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        '!',
        '>',
        '<',
        '_',
        '_',
        '<',
        '>',
        '$',
        '%',
        '%',
        '#',
        '#',
        '^',
        '^',
        '&',
        '&',
        '?',
        '?'
    );
    $par_Content = str_replace('@', '', $par_Content);
    $par_Content = preg_replace('~\s+~smi', ' ', $par_Content);
    $par_Content = str_replace($search, $replace, $par_Content);
    $par_Content = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function($m) {
        return "'" . chr(intval($m[1], 0)) . "'";
    }, $par_Content);
    
    $par_Content = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i', 'escapedHexToHex', $par_Content);
    $par_Content = preg_replace_callback('/\\\\([0-9]{1,3})/i', 'escapedOctDec', $par_Content);
    
    $par_Content = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $par_Content);
    $par_Content = preg_replace('/[\'"]\s*?\++\s*?[\'"]/smi', '', $par_Content);
    
    $content = str_replace('<?$', '<?php$', $content);
    $content = str_replace('<?php', '<?php ', $content);
    
    return $par_Content;
}

///////////////////////////////////////////////////////////////////////////
// Unicode BOM is U+FEFF, but after encoded, it will look like this.
define('UTF32_BIG_ENDIAN_BOM', chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF));
define('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00));
define('UTF16_BIG_ENDIAN_BOM', chr(0xFE) . chr(0xFF));
define('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE));
define('UTF8_BOM', chr(0xEF) . chr(0xBB) . chr(0xBF));

function detect_utf_encoding($text) {
    $first2 = substr($text, 0, 2);
    $first3 = substr($text, 0, 3);
    $first4 = substr($text, 0, 3);
    
    if ($first3 == UTF8_BOM)
        return 'UTF-8';
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM)
        return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM)
        return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM)
        return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM)
        return 'UTF-16LE';
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function QCR_SearchPHP($src) {
    if (preg_match("/(<\?php[\w\s]{5,})/smi", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }
    
    if (preg_match("/(<script[^>]*language\s*=\s*)('|\"|)php('|\"|)([^>]*>)/i", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }
    
    return false;
}


///////////////////////////////////////////////////////////////////////////
function knowUrl($par_URL) {
    global $g_UrlIgnoreList;
    
    for ($jk = 0; $jk < count($g_UrlIgnoreList); $jk++) {
        if (stripos($par_URL, $g_UrlIgnoreList[$jk]) !== false) {
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////

function makeSummary($par_Str, $par_Number, $par_Style) {
    return '<tr><td class="' . $par_Style . '" width=400>' . $par_Str . '</td><td class="' . $par_Style . '">' . $par_Number . '</td></tr>';
}

///////////////////////////////////////////////////////////////////////////

function CheckVulnerability($par_Filename, $par_Index, $par_Content) {
    global $g_Vulnerable, $g_CmsListDetector;
    
    
    $l_Vuln = array();
    
    $par_Filename = strtolower($par_Filename);
    
    if ((strpos($par_Filename, 'libraries/joomla/session/session.php') !== false) && (strpos($par_Content, '&& filter_var($_SERVER[\'HTTP_X_FORWARDED_FOR') === false)) {
        $l_Vuln['id']   = 'RCE : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if ((strpos($par_Filename, 'administrator/components/com_media/helpers/media.php') !== false) && (strpos($par_Content, '$format == \'\' || $format == false ||') === false)) {
        if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'joomla/filesystem/file.php') !== false) && (strpos($par_Content, '$file = rtrim($file, \'.\');') === false)) {
        if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'editor/filemanager/upload/test.html') !== false) || (stripos($par_Filename, 'editor/filemanager/browser/default/connectors/php/') !== false) || (stripos($par_Filename, 'editor/filemanager/connectors/uploadtest.html') !== false) || (strpos($par_Filename, 'editor/filemanager/browser/default/connectors/test.html') !== false)) {
        $l_Vuln['id']   = 'AFU : FCKEDITOR : http://www.exploit-db.com/exploits/17644/ & /exploit/249';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if ((strpos($par_Filename, 'inc_php/image_view.class.php') !== false) || (strpos($par_Filename, '/inc_php/framework/image_view.class.php') !== false)) {
        if (strpos($par_Content, 'showImageByID') === false) {
            $l_Vuln['id']   = 'AFU : REVSLIDER : http://www.exploit-db.com/exploits/35385/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'elfinder/php/connector.php') !== false) || (strpos($par_Filename, 'elfinder/elfinder.') !== false)) {
        $l_Vuln['id']   = 'AFU : elFinder';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if (strpos($par_Filename, 'includes/database/database.inc') !== false) {
        if (strpos($par_Content, 'foreach ($data as $i => $value)') !== false) {
            $l_Vuln['id']   = 'SQLI : DRUPAL : CVE-2014-3704';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'engine/classes/min/index.php') !== false) {
        if (strpos($par_Content, 'tr_replace(chr(0)') === false) {
            $l_Vuln['id']   = 'AFD : MINIFY : CVE-2013-6619';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'timthumb.php') !== false) || (strpos($par_Filename, 'thumb.php') !== false) || (strpos($par_Filename, 'cache.php') !== false) || (strpos($par_Filename, '_img.php') !== false)) {
        if (strpos($par_Content, 'code.google.com/p/timthumb') !== false && strpos($par_Content, '2.8.14') === false) {
            $l_Vuln['id']   = 'RCE : TIMTHUMB : CVE-2011-4106,CVE-2014-4663';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'components/com_rsform/helpers/rsform.php') !== false) {
        if (strpos($par_Content, 'eval($form->ScriptDisplay);') !== false) {
            $l_Vuln['id']   = 'RCE : RSFORM : rsform.php, LINE 1605';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'fancybox-for-wordpress/fancybox.php') !== false) {
        if (strpos($par_Content, '\'reset\' == $_REQUEST[\'action\']') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : FANCYBOX';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'cherry-plugin/admin/import-export/upload.php') !== false) {
        if (strpos($par_Content, 'verify nonce') === false) {
            $l_Vuln['id']   = 'AFU : Cherry Plugin';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'tiny_mce/plugins/tinybrowser/tinybrowser.php') !== false) {
        $l_Vuln['id']   = 'AFU : TINYMCE : http://www.exploit-db.com/exploits/9296/';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        
        return true;
    }
    
    if (strpos($par_Filename, '/bx_1c_import.php') !== false) {
        if (strpos($par_Content, '$_GET[\'action\']=="getfiles"') !== false) {
            $l_Vuln['id']   = 'AFD : https://habrahabr.ru/company/dsec/blog/326166/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            
            return true;
        }
    }
    
    if (strpos($par_Filename, 'scripts/setup.php') !== false) {
        if (strpos($par_Content, 'PMA_Config') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : PHPMYADMIN : http://1337day.com/exploit/5334';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, '/uploadify.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($tempFile,$targetFile') !== false) {
            $l_Vuln['id']   = 'AFU : UPLOADIFY : CVE: 2012-1153';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'com_adsmanager/controller.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($file[\'tmp_name\'], $tempPath.\'/\'.basename($file[') !== false) {
            $l_Vuln['id']   = 'AFU : https://revisium.com/ru/blog/adsmanager_afu.html';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'wp-content/plugins/wp-mobile-detector/resize.php') !== false) {
        if (strpos($par_Content, 'file_put_contents($path, file_get_contents($_REQUEST[\'src\']));') !== false) {
            $l_Vuln['id']   = 'AFU : https://www.pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'core/lib/drupal.php') !== false) {
        $version = '';
        if (preg_match('|VERSION\s*=\s*\'(8\.\d+\.\d+)\'|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }
        
        if (($version !== '') && (version_compare($version, '8.5.1', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        
        return false;
    }
    
    if (strpos($par_Filename, 'changelog.txt') !== false) {
        $version = '';
        if (preg_match('|Drupal\s+(7\.\d+),|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }
        
        if (($version !== '') && (version_compare($version, '7.58', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'phpmailer.php') !== false) {
        if (strpos($par_Content, 'PHPMailer') !== false) {
            $l_Found = preg_match('~Version:\s*(\d+)\.(\d+)\.(\d+)~', $par_Content, $l_Match);
            
            if ($l_Found) {
                $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                
                if ($l_Version < 2520) {
                    $l_Found = false;
                }
            }
            
            if (!$l_Found) {
                
                $l_Found = preg_match('~Version\s*=\s*\'(\d+)\.*(\d+)\.(\d+)~', $par_Content, $l_Match);
                if ($l_Found) {
                    $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                    if ($l_Version < 5220) {
                        $l_Found = false;
                    }
                }
            }
            
            
            if (!$l_Found) {
                $l_Vuln['id']   = 'RCE : CVE-2016-10045, CVE-2016-10031';
                $l_Vuln['ndx']  = $par_Index;
                $g_Vulnerable[] = $l_Vuln;
                return true;
            }
        }
        
        return false;
    }
    
    
    
    
}

///////////////////////////////////////////////////////////////////////////
function QCR_GoScan($par_Offset) {
    global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList, $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList, $g_Vulnerable;
    
    QCR_Debug('QCR_GoScan ' . $par_Offset);
    
    $i = 0;
    
    try {
        $s_file = new SplFileObject(QUEUE_FILENAME);
        $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        
        foreach ($s_file as $l_Filename) {
            QCR_ScanFile($l_Filename, $i++);
        }
        
        unset($s_file);
    }
    catch (Exception $e) {
        QCR_Debug($e->getMessage());
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ScanFile($l_Filename, $i = 0) {
    global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList, $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList, $g_Vulnerable, $g_CriticalFiles, $g_DeMapper;
    
    global $g_CRC;
    static $_files_and_ignored = 0;
    
    $l_CriticalDetected = false;
    $l_Stat             = stat($l_Filename);
    
    if (substr($l_Filename, -1) == DIR_SEPARATOR) {
        // FOLDER
        $g_Structure['n'][$i] = $l_Filename;
        $g_TotalFolder++;
        printProgress($_files_and_ignored, $l_Filename);
        return;
    }
    
    QCR_Debug('Scan file ' . $l_Filename);
    printProgress(++$_files_and_ignored, $l_Filename);
        
    // FILE
    if ((MAX_SIZE_TO_SCAN > 0 AND $l_Stat['size'] > MAX_SIZE_TO_SCAN) || ($l_Stat['size'] < 0)) {
        $g_BigFiles[] = $i;
        
        if (function_exists('aibolit_onBigFile')) {
            aibolit_onBigFile($l_Filename);
        }
        
        AddResult($l_Filename, $i);
        
        $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
        if ((!AI_HOSTER) && in_array($l_Ext, $g_CriticalFiles)) {
            $g_CriticalPHP[]         = $i;
            $g_CriticalPHPFragment[] = "BIG FILE. SKIPPED.";
            $g_CriticalPHPSig[]      = "big_1";
        }
    } else {
        $g_TotalFiles++;
        
        $l_TSStartScan = microtime(true);
        
        $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
        if (filetype($l_Filename) == 'file') {
            $l_Content   = @file_get_contents($l_Filename);
            $l_Unwrapped = @php_strip_whitespace($l_Filename);
        }
                
        if ((($l_Content == '') || ($l_Unwrapped == '')) && ($l_Stat['size'] > 0)) {
            $g_NotRead[] = $i;
            if (function_exists('aibolit_onReadError')) {
                aibolit_onReadError($l_Filename, 'io');
            }
            AddResult('[io] ' . $l_Filename, $i);
            return;
        }

        // ignore itself
        if (strpos($l_Content, '0b540f2fecff037cd1bc4465e634bcb7') !== false) {
           return false;
        }
        
        // unix executables
        if (strpos($l_Content, chr(127) . 'ELF') !== false) {
            // todo: add crc check 
            return;
        }
        
        $g_CRC = _hash_($l_Unwrapped);
        
        $l_UnicodeContent = detect_utf_encoding($l_Content);
        //$l_Unwrapped = $l_Content;
        
        // check vulnerability in files
        $l_CriticalDetected = CheckVulnerability($l_Filename, $i, $l_Content);
        
        if ($l_UnicodeContent !== false) {
            if (function_exists('iconv')) {
                $l_Unwrapped = iconv($l_UnicodeContent, "CP1251//IGNORE", $l_Unwrapped);
            } else {
                $g_NotRead[] = $i;
                if (function_exists('aibolit_onReadError')) {
                    aibolit_onReadError($l_Filename, 'ec');
                }
                AddResult('[ec] ' . $l_Filename, $i);
            }
        }
        
        // critical
        $g_SkipNextCheck = false;
        
        $l_DeobfType = '';
        if ((!AI_HOSTER) || AI_DEOBFUSCATE) {
            $l_DeobfType = getObfuscateType($l_Unwrapped);
        }
        
        if ($l_DeobfType != '') {
            $l_Unwrapped     = deobfuscate($l_Unwrapped);
            $g_SkipNextCheck = checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType);
        } else {
            if (DEBUG_MODE) {
                stdOut("\n...... NOT OBFUSCATED\n");
            }
        }
        
        $l_Unwrapped = UnwrapObfu($l_Unwrapped);
        
        if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Unwrapped, $l_Pos, $l_SigId)) {
            if ($l_Ext == 'js') {
                $g_CriticalJS[]         = $i;
                $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $g_CriticalJSSig[]      = $l_SigId;
            } else {
                $g_CriticalPHP[]         = $i;
                $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $g_CriticalPHPSig[]      = $l_SigId;
            }
            
            $g_SkipNextCheck = true;
        } else {
            if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Content, $l_Pos, $l_SigId)) {
                if ($l_Ext == 'js') {
                    $g_CriticalJS[]         = $i;
                    $g_CriticalJSFragment[] = getFragment($l_Content, $l_Pos);
                    $g_CriticalJSSig[]      = $l_SigId;
                } else {
                    $g_CriticalPHP[]         = $i;
                    $g_CriticalPHPFragment[] = getFragment($l_Content, $l_Pos);
                    $g_CriticalPHPSig[]      = $l_SigId;
                }
                
                $g_SkipNextCheck = true;
            }
        }
        
        $l_TypeDe = 0;
        
        // critical JS
        if (!$g_SkipNextCheck) {
            $l_Pos = CriticalJS($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos !== false) {
                if ($l_Ext == 'js') {
                    $g_CriticalJS[]         = $i;
                    $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $g_CriticalJSSig[]      = $l_SigId;
                } else {
                    $g_CriticalPHP[]         = $i;
                    $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $g_CriticalPHPSig[]      = $l_SigId;
                }
                
                $g_SkipNextCheck = true;
            }
        }
        
        // phishing
        if (!$g_SkipNextCheck) {
            $l_Pos = Phishing($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos === false) {
                $l_Pos = Phishing($l_Filename, $i, $l_Content, $l_SigId);
            }
            
            if ($l_Pos !== false) {
                $g_Phishing[]            = $i;
                $g_PhishingFragment[]    = getFragment($l_Unwrapped, $l_Pos);
                $g_PhishingSigFragment[] = $l_SigId;
                $g_SkipNextCheck         = true;
            }
        }
        
        
        if (!$g_SkipNextCheck) {
            // warnings
            $l_Pos = '';
            
            // adware
            if (Adware($l_Filename, $l_Unwrapped, $l_Pos)) {
                $g_AdwareList[]         = $i;
                $g_AdwareListFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $l_CriticalDetected     = true;
            }
            
            // articles
            if (stripos($l_Filename, 'article_index')) {
                $g_AdwareList[]     = $i;
                $l_CriticalDetected = true;
            }
        }
    } // end of if (!$g_SkipNextCheck) {
    
    unset($l_Unwrapped);
    unset($l_Content);
    
    //printProgress(++$_files_and_ignored, $l_Filename);
    
    $l_TSEndScan = microtime(true);
    if ($l_TSEndScan - $l_TSStartScan >= 0.5) {
        usleep(SCAN_DELAY * 1000);
    }
    
    if ($g_SkipNextCheck || $l_CriticalDetected) {
        AddResult($l_Filename, $i);
    }
}

function AddResult($l_Filename, $i) {
    global $g_Structure, $g_CRC;
    
    $l_Stat                 = stat($l_Filename);
    $g_Structure['n'][$i]   = $l_Filename;
    $g_Structure['s'][$i]   = $l_Stat['size'];
    $g_Structure['c'][$i]   = $l_Stat['ctime'];
    $g_Structure['m'][$i]   = $l_Stat['mtime'];
    $g_Structure['crc'][$i] = $g_CRC;
}

///////////////////////////////////////////////////////////////////////////
function WarningPHP($l_FN, $l_Content, &$l_Pos, &$l_SigId) {
    global $g_SusDB, $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
    
    $l_Res = false;
    
    if (AI_EXTRA_WARN) {
        foreach ($g_SusDB as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    return true;
                }
            }
        }
    }
    
    if (AI_EXPERT < 2) {
        foreach ($gXX_FlexDBShe as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                return true;
            }
        }
        
    }
    
    if (AI_EXPERT < 1) {
        foreach ($gX_FlexDBShe as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                return true;
            }
        }
        
        $l_Content_lo = strtolower($l_Content);
        
        foreach ($gX_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = myCheckSum($l_Item);
                return true;
            }
        }
    }
    
}

///////////////////////////////////////////////////////////////////////////
function Adware($l_FN, $l_Content, &$l_Pos) {
    global $g_AdwareSig;
    
    $l_Res = false;
    
    foreach ($g_AdwareSig as $l_Item) {
        $offset = 0;
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos = $l_Found[0][1];
                return true;
            }
            
            $offset = $l_Found[0][1] + 1;
        }
    }
    
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CheckException(&$l_Content, &$l_Found) {
    global $g_ExceptFlex, $gX_FlexDBShe, $gXX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
    $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);
    
    foreach ($g_ExceptFlex as $l_ExceptItem) {
        if (@preg_match('#' . $l_ExceptItem . '#smi', $l_FoundStrPlus, $l_Detected)) {
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function Phishing($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_PhishingSig, $g_PhishFiles, $g_PhishEntries;
    
    $l_Res = false;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_PhishFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_PhishEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped phs file, not critical.\n";
        }
        
        return false;
    }
    
    
    foreach ($g_PhishingSig as $l_Item) {
        $offset = 0;
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "Phis: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return $l_Pos;
            }
            $offset = $l_Found[0][1] + 1;
            
        }
    }
    
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CriticalJS($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_JSVirSig, $gX_JSVirSig, $g_VirusFiles, $g_VirusEntries, $g_RegExpStat;
    
    $l_Res = false;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_VirusFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_VirusEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped js file, not critical.\n";
        }
        
        return false;
    }
    
    
    foreach ($g_JSVirSig as $l_Item) {
        $offset = 0;
        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }
        
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "JS: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return $l_Pos;
            }
            
            $offset = $l_Found[0][1] + 1;
            
        }
        
        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }
        
    }
    
    if (AI_EXPERT > 1) {
        foreach ($gX_JSVirSig as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "JS PARA: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return $l_Pos;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    return $l_Res;
}

////////////////////////////////////////////////////////////////////////////
function pcre_error($par_FN, $par_Index) {
    global $g_NotRead, $g_Structure;
    
    $err = preg_last_error();
    if (($err == PREG_BACKTRACK_LIMIT_ERROR) || ($err == PREG_RECURSION_LIMIT_ERROR)) {
        if (!in_array($par_Index, $g_NotRead)) {
            if (function_exists('aibolit_onReadError')) {
                aibolit_onReadError($l_Filename, 're');
            }
            $g_NotRead[] = $par_Index;
            AddResult('[re] ' . $par_FN, $par_Index);
        }
        
        return true;
    }
    
    return false;
}



////////////////////////////////////////////////////////////////////////////
define('SUSP_MTIME', 1); // suspicious mtime (greater than ctime)
define('SUSP_PERM', 2); // suspicious permissions 
define('SUSP_PHP_IN_UPLOAD', 3); // suspicious .php file in upload or image folder 

function get_descr_heur($type) {
    switch ($type) {
        case SUSP_MTIME:
            return AI_STR_077;
        case SUSP_PERM:
            return AI_STR_078;
        case SUSP_PHP_IN_UPLOAD:
            return AI_STR_079;
    }
    
    return "---";
}

///////////////////////////////////////////////////////////////////////////
function CriticalPHP($l_FN, $l_Index, $l_Content, &$l_Pos, &$l_SigId) {
    global $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment, $g_CriticalFiles, $g_CriticalEntries, $g_RegExpStat;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_CriticalFiles as $l_Ext) {
            if ((strpos($l_FN, $l_Ext) !== false) && (strpos($l_FN, '.js') === false)) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_CriticalEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    
    // if not critical - skip it 
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped file, not critical.\n";
        }
        
        return false;
    }
    
    foreach ($g_FlexDBShe as $l_Item) {
        $offset = 0;
        
        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }
        
        while (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                //$l_SigId = myCheckSum($l_Item);
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "CRIT 1: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return true;
            }
            
            $offset = $l_Found[0][1] + 1;
            
        }
        
        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }
        
    }
    
    if (AI_EXPERT > 0) {
        foreach ($gX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "CRIT 3: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return true;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    if (AI_EXPERT > 1) {
        foreach ($gXX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "CRIT 2: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return true;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    $l_Content_lo = strtolower($l_Content);
    
    foreach ($g_DBShe as $l_Item) {
        $l_Pos = strpos($l_Content_lo, $l_Item);
        if ($l_Pos !== false) {
            $l_SigId = myCheckSum($l_Item);
            
            if (DEBUG_MODE) {
                echo "CRIT 4: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    if (AI_EXPERT > 0) {
        foreach ($gX_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = myCheckSum($l_Item);
                
                if (DEBUG_MODE) {
                    echo "CRIT 5: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return true;
            }
        }
    }
    
    if (AI_HOSTER)
        return false;
    
    if (AI_EXPERT > 0) {
        if ((strpos($l_Content, 'GIF89') === 0) && (strpos($l_FN, '.php') !== false)) {
            $l_Pos = 0;
            
            if (DEBUG_MODE) {
                echo "CRIT 6: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    // detect uploaders / droppers
    if (AI_EXPERT > 1) {
        $l_Found = null;
        if ((filesize($l_FN) < 2048) && (strpos($l_FN, '.ph') !== false) && ((($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) || (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) || (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)))) {
            if ($l_Found != null) {
                $l_Pos = $l_Found[0][1];
            }
            if (DEBUG_MODE) {
                echo "CRIT 7: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
if (!isCli()) {
    header('Content-type: text/html; charset=utf-8');
}

if (!isCli()) {
    
    $l_PassOK = false;
    if (strlen(PASS) > 8) {
        $l_PassOK = true;
    }
    
    if ($l_PassOK && preg_match('|[0-9]|', PASS, $l_Found) && preg_match('|[A-Z]|', PASS, $l_Found) && preg_match('|[a-z]|', PASS, $l_Found)) {
        $l_PassOK = true;
    }
    
    if (!$l_PassOK) {
        echo sprintf(AI_STR_009, generatePassword());
        exit;
    }
    
    if (isset($_GET['fn']) && ($_GET['ph'] == crc32(PASS))) {
        printFile();
        exit;
    }
    
    if ($_GET['p'] != PASS) {
        $generated_pass = generatePassword();
        echo sprintf(AI_STR_010, $generated_pass, $generated_pass);
        exit;
    }
}

if (!is_readable(ROOT_PATH)) {
    echo AI_STR_011;
    exit;
}

if (isCli()) {
    if (defined('REPORT_PATH') AND REPORT_PATH) {
        if (!is_writable(REPORT_PATH)) {
            die2("\nCannot write report. Report dir " . REPORT_PATH . " is not writable.");
        }
        
        else if (!REPORT_FILE) {
            die2("\nCannot write report. Report filename is empty.");
        }
        
        else if (($file = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE) AND is_file($file) AND !is_writable($file)) {
            die2("\nCannot write report. Report file '$file' exists but is not writable.");
        }
    }
}


// detect version CMS
$g_KnownCMS        = array();
$tmp_cms           = array();
$g_CmsListDetector = new CmsVersionDetector(ROOT_PATH);
$l_CmsDetectedNum  = $g_CmsListDetector->getCmsNumber();
for ($tt = 0; $tt < $l_CmsDetectedNum; $tt++) {
    $g_CMS[]                                                  = $g_CmsListDetector->getCmsName($tt) . ' v' . makeSafeFn($g_CmsListDetector->getCmsVersion($tt));
    $tmp_cms[strtolower($g_CmsListDetector->getCmsName($tt))] = 1;
}

if (count($tmp_cms) > 0) {
    $g_KnownCMS = array_keys($tmp_cms);
    $len        = count($g_KnownCMS);
    for ($i = 0; $i < $len; $i++) {
        if ($g_KnownCMS[$i] == strtolower(CMS_WORDPRESS))
            $g_KnownCMS[] = 'wp';
        if ($g_KnownCMS[$i] == strtolower(CMS_WEBASYST))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CMS_IPB))
            $g_KnownCMS[] = 'ipb';
        if ($g_KnownCMS[$i] == strtolower(CMS_DLE))
            $g_KnownCMS[] = 'dle';
        if ($g_KnownCMS[$i] == strtolower(CMS_INSTANTCMS))
            $g_KnownCMS[] = 'instantcms';
        if ($g_KnownCMS[$i] == strtolower(CMS_SHOPSCRIPT))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CMS_DRUPAL))
            $g_KnownCMS[] = 'drupal';
    }
}


$g_DirIgnoreList = array();
$g_IgnoreList    = array();
$g_UrlIgnoreList = array();
$g_KnownList     = array();

$l_IgnoreFilename    = $g_AiBolitAbsolutePath . '/.aignore';
$l_DirIgnoreFilename = $g_AiBolitAbsolutePath . '/.adirignore';
$l_UrlIgnoreFilename = $g_AiBolitAbsolutePath . '/.aurlignore';

if (file_exists($l_IgnoreFilename)) {
    $l_IgnoreListRaw = file($l_IgnoreFilename);
    for ($i = 0; $i < count($l_IgnoreListRaw); $i++) {
        $g_IgnoreList[] = explode("\t", trim($l_IgnoreListRaw[$i]));
    }
    unset($l_IgnoreListRaw);
}

if (file_exists($l_DirIgnoreFilename)) {
    $g_DirIgnoreList = file($l_DirIgnoreFilename);
    
    for ($i = 0; $i < count($g_DirIgnoreList); $i++) {
        $g_DirIgnoreList[$i] = trim($g_DirIgnoreList[$i]);
    }
}

if (file_exists($l_UrlIgnoreFilename)) {
    $g_UrlIgnoreList = file($l_UrlIgnoreFilename);
    
    for ($i = 0; $i < count($g_UrlIgnoreList); $i++) {
        $g_UrlIgnoreList[$i] = trim($g_UrlIgnoreList[$i]);
    }
}


$l_SkipMask = array(
    '/template_\w{32}.css',
    '/cache/templates/.{1,150}\.tpl\.php',
    '/system/cache/templates_c/\w{1,40}\.php',
    '/assets/cache/rss/\w{1,60}',
    '/cache/minify/minify_\w{32}',
    '/cache/page/\w{32}\.php',
    '/cache/object/\w{1,10}/\w{1,10}/\w{1,10}/\w{32}\.php',
    '/cache/wp-cache-\d{32}\.php',
    '/cache/page/\w{32}\.php_expire',
    '/cache/page/\w{32}-cache-page-\w{32}\.php',
    '\w{32}-cache-com_content-\w{32}\.php',
    '\w{32}-cache-mod_custom-\w{32}\.php',
    '\w{32}-cache-mod_templates-\w{32}\.php',
    '\w{32}-cache-_system-\w{32}\.php',
    '/cache/twig/\w{1,32}/\d+/\w{1,100}\.php',
    '/autoptimize/js/autoptimize_\w{32}\.js',
    '/bitrix/cache/\w{32}\.php',
    '/bitrix/cache/.{1,200}/\w{32}\.php',
    '/bitrix/cache/iblock_find/',
    '/bitrix/managed_cache/MYSQL/user_option/[^/]+/',
    '/bitrix/cache/s1/bitrix/catalog\.section/',
    '/bitrix/cache/s1/bitrix/catalog\.element/',
    '/bitrix/cache/s1/bitrix/menu/',
    '/catalog.element/[^/]+/[^/]+/\w{32}\.php',
    '/bitrix/managed\_cache/.{1,150}/\.\w{32}\.php',
    '/core/cache/mgr/smarty/default/.{1,100}\.tpl\.php',
    '/core/cache/resource/web/resources/[0-9]{1,50}\.cache\.php',
    '/smarty/compiled/SC/.{1,100}/%%.{1,200}\.php',
    '/smarty/.{1,150}\.tpl\.php',
    '/smarty/compile/.{1,150}\.tpl\.cache\.php',
    '/files/templates_c/.{1,150}\.html\.php',
    '/uploads/javascript_global/.{1,150}\.js',
    '/assets/cache/rss/\w{32}',
    'сore/cache/resource/web/resources/\d+\.cache\.php',
    '/assets/cache/docid_\d+_\w{32}\.pageCache\.php',
    '/t3-assets/dev/t3/.{1,150}-cache-\w{1,20}-.{1,150}\.php',
    '/t3-assets/js/js-\w{1,30}\.js',
    '/temp/cache/SC/.{1,100}/\.cache\..{1,100}\.php',
    '/tmp/sess\_\w{32}$',
    '/assets/cache/docid\_.{1,100}\.pageCache\.php',
    '/stat/usage\_\w{1,100}\.html',
    '/stat/site\_\w{1,100}\.html',
    '/gallery/item/list/\w{1,100}\.cache\.php',
    '/core/cache/registry/.{1,100}/ext-.{1,100}\.php',
    '/core/cache/resource/shk\_/\w{1,50}\.cache\.php',
    '/cache/\w{1,40}/\w+-cache-\w+-\w{32,40}\.php',
    '/webstat/awstats.{1,150}\.txt',
    '/awstats/awstats.{1,150}\.txt',
    '/awstats/.{1,80}\.pl',
    '/awstats/.{1,80}\.html',
    '/inc/min/styles_\w+\.min\.css',
    '/inc/min/styles_\w+\.min\.js',
    '/logs/error\_log\.',
    '/logs/xferlog\.',
    '/logs/access_log\.',
    '/logs/cron\.',
    '/logs/exceptions/.{1,200}\.log$',
    '/hyper-cache/[^/]{1,50}/[^/]{1,50}/[^/]{1,50}/index\.html',
    '/mail/new/[^,]+,S=[^,]+,W=',
    '/mail/new/[^,]=,S=',
    '/application/logs/\d+/\d+/\d+\.php',
    '/sites/default/files/js/js_\w{32}\.js',
    '/yt-assets/\w{32}\.css',
    '/wp-content/cache/object/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/catalog\.section/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/simpla/design/compiled/[\w\.]{40,60}\.php',
    '/compile/\w{2}/\w{2}/\w{2}/[\w.]{40,80}\.php',
    '/sys-temp/static-cache/[^/]{1,60}/userCache/[\w\./]{40,100}\.php',
    '/session/sess_\w{32}',
    '/webstat/awstats\.[\w\./]{3,100}\.html',
    '/stat/webalizer\.current',
    '/stat/usage_\d+\.html'
);

$l_SkipSample = array();

if (SMART_SCAN) {
    $g_DirIgnoreList = array_merge($g_DirIgnoreList, $l_SkipMask);
}

QCR_Debug();

// Load custom signatures
if (file_exists($g_AiBolitAbsolutePath . "/ai-bolit.sig")) {
   try {
       $s_file = new SplFileObject($g_AiBolitAbsolutePath . "/ai-bolit.sig");
       $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
       foreach ($s_file as $line) {
           $g_FlexDBShe[] = preg_replace('~\G(?:[^#\\\\]+|\\\\.)*+\K#~', '\\#', $line); // escaping #
       }

       stdOut("Loaded " . $s_file->key() . " signatures from ai-bolit.sig");
       $s_file = null; // file handler is closed
   }
   catch (Exception $e) {
       QCR_Debug("Import ai-bolit.sig " . $e->getMessage());
   }
}

QCR_Debug();

$defaults['skip_ext'] = strtolower(trim($defaults['skip_ext']));
if ($defaults['skip_ext'] != '') {
    $g_IgnoredExt = explode(',', $defaults['skip_ext']);
    for ($i = 0; $i < count($g_IgnoredExt); $i++) {
        $g_IgnoredExt[$i] = trim($g_IgnoredExt[$i]);
    }
    
    QCR_Debug('Skip files with extensions: ' . implode(',', $g_IgnoredExt));
    stdOut('Skip extensions: ' . implode(',', $g_IgnoredExt));
}

// scan single file
if (defined('SCAN_FILE')) {
    if (file_exists(SCAN_FILE) && is_file(SCAN_FILE) && is_readable(SCAN_FILE)) {
        stdOut("Start scanning file '" . SCAN_FILE . "'.");
        QCR_ScanFile(SCAN_FILE);
    } else {
        stdOut("Error:" . SCAN_FILE . " either is not a file or readable");
    }
} else {
    if (isset($_GET['2check'])) {
        $options['with-2check'] = 1;
    }
    
    $use_doublecheck = isset($options['with-2check']) && file_exists(DOUBLECHECK_FILE);
    $use_listingfile = defined('LISTING_FILE');
    
    // scan list of files from file
    if (!(ICHECK || IMAKE) && ($use_doublecheck || $use_listingfile)) {
        if ($use_doublecheck) {
            $listing = DOUBLECHECK_FILE;
        } else {
            if ($use_listingfile) {
                $listing = LISTING_FILE;
            }
        }
        
        stdOut("Start scanning the list from '" . $listing . "'.\n");

        if ($listing == 'stdin') {
           $lines = explode("\n", getStdin());
        } else {
           $lines = file($listing);
        }

        for ($i = 0, $size = count($lines); $i < $size; $i++) {
            $lines[$i] = trim($lines[$i]);
            if (empty($lines[$i]))
                unset($lines[$i]);
        }
        
        $i = 0;
        if ($use_doublecheck) {
            /* skip first line with <?php die("Forbidden"); ?> */
            unset($lines[0]);
            $i = 1;
        }
        
        $g_FoundTotalFiles = count($lines);
        foreach ($lines as $l_FN) {
            is_dir($l_FN) && $g_TotalFolder++;
            printProgress($i++, $l_FN);
            $BOOL_RESULT = true; // display disable
            is_file($l_FN) && QCR_ScanFile($l_FN, $i);
            $BOOL_RESULT = false; // display enable
        }
        
        $g_FoundTotalDirs  = $g_TotalFolder;
        $g_FoundTotalFiles = $g_TotalFiles;
        
    } else {
        // scan whole file system
        stdOut("Start scanning '" . ROOT_PATH . "'.\n");
        
        file_exists(QUEUE_FILENAME) && unlink(QUEUE_FILENAME);
        if (ICHECK || IMAKE) {
            // INTEGRITY CHECK
            IMAKE and unlink(INTEGRITY_DB_FILE);
            ICHECK and load_integrity_db();
            QCR_IntegrityCheck(ROOT_PATH);
            stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
            if (IMAKE)
                exit(0);
            if (ICHECK) {
                $i       = $g_Counter;
                $g_CRC   = 0;
                $changes = array();
                $ref =& $g_IntegrityDB;
                foreach ($g_IntegrityDB as $l_FileName => $type) {
                    unset($g_IntegrityDB[$l_FileName]);
                    $l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
                    if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                        continue;
                    }
                    for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                        if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                            continue 2;
                        }
                    }
                    $type = in_array($type, array(
                        'added',
                        'modified'
                    )) ? $type : 'deleted';
                    $type .= substr($l_FileName, -1) == '/' ? 'Dirs' : 'Files';
                    $changes[$type][] = ++$i;
                    AddResult($l_FileName, $i);
                }
                $g_FoundTotalFiles = count($changes['addedFiles']) + count($changes['modifiedFiles']);
                stdOut("Found changes " . count($changes['modifiedFiles']) . " files and added " . count($changes['addedFiles']) . " files.");
            }
            
        } else {
            QCR_ScanDirectories(ROOT_PATH);
            stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
        }
        
        QCR_Debug();
        stdOut(str_repeat(' ', 160), false);
        QCR_GoScan(0);
        unlink(QUEUE_FILENAME);
        if (defined('PROGRESS_LOG_FILE') && file_exists(PROGRESS_LOG_FILE))
            @unlink(PROGRESS_LOG_FILE);
    }
}

QCR_Debug();

if (true) {
    $g_HeuristicDetected = array();
    $g_Iframer           = array();
    $g_Base64            = array();
}


// whitelist

$snum = 0;
$list = check_whitelist($g_Structure['crc'], $snum);

foreach (array(
    'g_CriticalPHP',
    'g_CriticalJS',
    'g_Iframer',
    'g_Base64',
    'g_Phishing',
    'g_AdwareList',
    'g_Redirect'
) as $p) {
    if (empty($$p))
        continue;
    
    $p_Fragment = $p . "Fragment";
    $p_Sig      = $p . "Sig";
    if ($p == 'g_Redirect')
        $p_Fragment = $p . "PHPFragment";
    if ($p == 'g_Phishing')
        $p_Sig = $p . "SigFragment";
    
    $count = count($$p);
    for ($i = 0; $i < $count; $i++) {
        $id = "{${$p}[$i]}";
        if (in_array($g_Structure['crc'][$id], $list)) {
            unset($GLOBALS[$p][$i]);
            unset($GLOBALS[$p_Sig][$i]);
            unset($GLOBALS[$p_Fragment][$i]);
        }
    }
    
    $$p          = array_values($$p);
    $$p_Fragment = array_values($$p_Fragment);
    if (!empty($$p_Sig))
        $$p_Sig = array_values($$p_Sig);
}


////////////////////////////////////////////////////////////////////////////
if (AI_HOSTER) {
    $g_IframerFragment       = array();
    $g_Iframer               = array();
    $g_Redirect              = array();
    $g_Doorway               = array();
    $g_EmptyLink             = array();
    $g_HeuristicType         = array();
    $g_HeuristicDetected     = array();
    $g_WarningPHP            = array();
    $g_AdwareList            = array();
    $g_Phishing              = array();
    $g_PHPCodeInside         = array();
    $g_PHPCodeInsideFragment = array();
    $g_WarningPHPFragment    = array();
    $g_WarningPHPSig         = array();
    $g_BigFiles              = array();
    $g_RedirectPHPFragment   = array();
    $g_EmptyLinkSrc          = array();
    $g_Base64Fragment        = array();
    $g_UnixExec              = array();
    $g_PhishingSigFragment   = array();
    $g_PhishingFragment      = array();
    $g_PhishingSig           = array();
    $g_IframerFragment       = array();
    $g_CMS                   = array();
    $g_AdwareListFragment    = array();
}

if (BOOL_RESULT && (!defined('NEED_REPORT'))) {
    if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_PhishingSig) > 0)) {
        exit(2);
    } else {
        exit(0);
    }
}
////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@SERVICE_INFO@@", htmlspecialchars("[" . $int_enc . "][" . $snum . "]"), $l_Template);

$l_Template = str_replace("@@PATH_URL@@", (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $g_AddPrefix . str_replace($g_NoPrefix, '', addSlash(ROOT_PATH))), $l_Template);

$time_taken = seconds2Human(microtime(true) - START_TIME);

$l_Template = str_replace("@@SCANNED@@", sprintf(AI_STR_013, $g_TotalFolder, $g_TotalFiles), $l_Template);

$l_ShowOffer = false;

stdOut("\nBuilding report [ mode = " . AI_EXPERT . " ]\n");

//stdOut("\nLoaded signatures: " . count($g_FlexDBShe) . " / " . count($g_JSVirSig) . "\n");

////////////////////////////////////////////////////////////////////////////
// save 
if (!(ICHECK || IMAKE))
    if (isset($options['with-2check']) || isset($options['quarantine']))
        if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_Base64) > 0) OR (count($g_Iframer) > 0) OR (count($g_UnixExec))) {
            if (!file_exists(DOUBLECHECK_FILE)) {
                if ($l_FH = fopen(DOUBLECHECK_FILE, 'w')) {
                    fputs($l_FH, '<?php die("Forbidden"); ?>' . "\n");
                    
                    $l_CurrPath = dirname(__FILE__);
                    
                    if (!isset($g_CriticalPHP)) {
                        $g_CriticalPHP = array();
                    }
                    if (!isset($g_CriticalJS)) {
                        $g_CriticalJS = array();
                    }
                    if (!isset($g_Iframer)) {
                        $g_Iframer = array();
                    }
                    if (!isset($g_Base64)) {
                        $g_Base64 = array();
                    }
                    if (!isset($g_Phishing)) {
                        $g_Phishing = array();
                    }
                    if (!isset($g_AdwareList)) {
                        $g_AdwareList = array();
                    }
                    if (!isset($g_Redirect)) {
                        $g_Redirect = array();
                    }
                    
                    $tmpIndex = array_merge($g_CriticalPHP, $g_CriticalJS, $g_Phishing, $g_Base64, $g_Iframer, $g_AdwareList, $g_Redirect);
                    $tmpIndex = array_values(array_unique($tmpIndex));
                    
                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        $tmpIndex[$i] = str_replace($l_CurrPath, '.', $g_Structure['n'][$tmpIndex[$i]]);
                    }
                    
                    for ($i = 0; $i < count($g_UnixExec); $i++) {
                        $tmpIndex[] = str_replace($l_CurrPath, '.', $g_UnixExec[$i]);
                    }
                    
                    $tmpIndex = array_values(array_unique($tmpIndex));
                    
                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        fputs($l_FH, $tmpIndex[$i] . "\n");
                    }
                    
                    fclose($l_FH);
                } else {
                    stdOut("Error! Cannot create " . DOUBLECHECK_FILE);
                }
            } else {
                stdOut(DOUBLECHECK_FILE . ' already exists.');
                if (AI_STR_044 != '')
                    $l_Result .= '<div class="rep">' . AI_STR_044 . '</div>';
            }
            
        }

////////////////////////////////////////////////////////////////////////////

$l_Summary = '<div class="title">' . AI_STR_074 . '</div>';
$l_Summary .= '<table cellspacing=0 border=0>';

if (count($g_Redirect) > 0) {
    $l_Summary .= makeSummary(AI_STR_059, count($g_Redirect), "crit");
}

if (count($g_CriticalPHP) > 0) {
    $l_Summary .= makeSummary(AI_STR_060, count($g_CriticalPHP), "crit");
}

if (count($g_CriticalJS) > 0) {
    $l_Summary .= makeSummary(AI_STR_061, count($g_CriticalJS), "crit");
}

if (count($g_Phishing) > 0) {
    $l_Summary .= makeSummary(AI_STR_062, count($g_Phishing), "crit");
}

if (count($g_NotRead) > 0) {
    $l_Summary .= makeSummary(AI_STR_066, count($g_NotRead), "crit");
}

if (count($g_BigFiles) > 0) {
    $l_Summary .= makeSummary(AI_STR_065, count($g_BigFiles), "warn");
}

if (count($g_SymLinks) > 0) {
    $l_Summary .= makeSummary(AI_STR_069, count($g_SymLinks), "warn");
}

$l_Summary .= "</table>";

$l_ArraySummary                      = array();
$l_ArraySummary["redirect"]          = count($g_Redirect);
$l_ArraySummary["critical_php"]      = count($g_CriticalPHP);
$l_ArraySummary["critical_js"]       = count($g_CriticalJS);
$l_ArraySummary["phishing"]          = count($g_Phishing);
$l_ArraySummary["unix_exec"]         = 0; // count($g_UnixExec);
$l_ArraySummary["iframes"]           = 0; // count($g_Iframer);
$l_ArraySummary["not_read"]          = count($g_NotRead);
$l_ArraySummary["base64"]            = 0; // count($g_Base64);
$l_ArraySummary["heuristics"]        = 0; // count($g_HeuristicDetected);
$l_ArraySummary["symlinks"]          = count($g_SymLinks);
$l_ArraySummary["big_files_skipped"] = count($g_BigFiles);

if (function_exists('json_encode')) {
    $l_Summary .= "<!--[json]" . json_encode($l_ArraySummary) . "[/json]-->";
}

$l_Summary .= "<div class=details style=\"margin: 20px 20px 20px 0\">" . AI_STR_080 . "</div>\n";

$l_Template = str_replace("@@SUMMARY@@", $l_Summary, $l_Template);

$l_Result .= AI_STR_015;

$l_Template = str_replace("@@VERSION@@", AI_VERSION, $l_Template);

////////////////////////////////////////////////////////////////////////////



if (function_exists("gethostname") && is_callable("gethostname")) {
    $l_HostName = gethostname();
} else {
    $l_HostName = '???';
}

$l_PlainResult = "# Malware list detected by AI-Bolit (https://revisium.com/ai/) on " . date("d/m/Y H:i:s", time()) . " " . $l_HostName . "\n\n";

$l_RawReport = array();

$l_RawReport['summary'] = array(
    'scan_path' => $defaults['path'],
    'report_time' => time(),
    'scan_time' => round(microtime(true) - START_TIME, 1),
    'total_files' => $g_FoundTotalFiles,
    'counters' => $l_ArraySummary,
    'ai_version' => AI_VERSION
);

if (!AI_HOSTER) {
    stdOut("Building list of vulnerable scripts " . count($g_Vulnerable));
    
    if (count($g_Vulnerable) > 0) {
        $l_Result .= '<div class="note_vir">' . AI_STR_081 . ' (' . count($g_Vulnerable) . ')</div><div class="crit">';
        foreach ($g_Vulnerable as $l_Item) {
            $l_Result .= '<li>' . makeSafeFn($g_Structure['n'][$l_Item['ndx']], true) . ' - ' . $l_Item['id'] . '</li>';
            $l_PlainResult .= '[VULNERABILITY] ' . replacePathArray($g_Structure['n'][$l_Item['ndx']]) . ' - ' . $l_Item['id'] . "\n";
        }
        
        $l_Result .= '</div><p>' . PHP_EOL;
        $l_PlainResult .= "\n";
    }
}


stdOut("Building list of shells " . count($g_CriticalPHP));

$l_RawReport['vulners'] = getRawJsonVuln($g_Vulnerable);

if (count($g_CriticalPHP) > 0) {
    $g_CriticalPHP              = array_slice($g_CriticalPHP, 0, 15000);
    $l_RawReport['php_malware'] = getRawJson($g_CriticalPHP, $g_CriticalPHPFragment, $g_CriticalPHPSig);
    $l_Result .= '<div class="note_vir">' . AI_STR_016 . ' (' . count($g_CriticalPHP) . ')</div><div class="crit">';
    $l_Result .= printList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit');
    $l_PlainResult .= '[SERVER MALWARE]' . "\n" . printPlainList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit') . "\n";
    $l_Result .= '</div>' . PHP_EOL;
    
    $l_ShowOffer = true;
} else {
    $l_Result .= '<div class="ok"><b>' . AI_STR_017 . '</b></div>';
}

stdOut("Building list of js " . count($g_CriticalJS));

if (count($g_CriticalJS) > 0) {
    $g_CriticalJS              = array_slice($g_CriticalJS, 0, 15000);
    $l_RawReport['js_malware'] = getRawJson($g_CriticalJS, $g_CriticalJSFragment, $g_CriticalJSSig);
    $l_Result .= '<div class="note_vir">' . AI_STR_018 . ' (' . count($g_CriticalJS) . ')</div><div class="crit">';
    $l_Result .= printList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir');
    $l_PlainResult .= '[CLIENT MALWARE / JS]' . "\n" . printPlainList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir') . "\n";
    $l_Result .= "</div>" . PHP_EOL;
    
    $l_ShowOffer = true;
}

stdOut("Building list of unread files " . count($g_NotRead));

if (count($g_NotRead) > 0) {
    $g_NotRead               = array_slice($g_NotRead, 0, AIBOLIT_MAX_NUMBER);
    $l_RawReport['not_read'] = $g_NotRead;
    $l_Result .= '<div class="note_vir">' . AI_STR_030 . ' (' . count($g_NotRead) . ')</div><div class="crit">';
    $l_Result .= printList($g_NotRead);
    $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
    $l_PlainResult .= '[SCAN ERROR / SKIPPED]' . "\n" . printPlainList($g_NotRead) . "\n\n";
}

if (!AI_HOSTER) {
    stdOut("Building list of phishing pages " . count($g_Phishing));
    
    if (count($g_Phishing) > 0) {
        $l_RawReport['phishing'] = getRawJson($g_Phishing, $g_PhishingFragment, $g_PhishingSigFragment);
        $l_Result .= '<div class="note_vir">' . AI_STR_058 . ' (' . count($g_Phishing) . ')</div><div class="crit">';
        $l_Result .= printList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir');
        $l_PlainResult .= '[PHISHING]' . "\n" . printPlainList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir') . "\n";
        $l_Result .= "</div>" . PHP_EOL;
        
        $l_ShowOffer = true;
    }
    
    stdOut("Building list of redirects " . count($g_Redirect));
    if (count($g_Redirect) > 0) {
        $l_RawReport['redirect'] = getRawJson($g_Redirect, $g_RedirectPHPFragment);
        $l_ShowOffer             = true;
        $l_Result .= '<div class="note_vir">' . AI_STR_027 . ' (' . count($g_Redirect) . ')</div><div class="crit">';
        $l_Result .= printList($g_Redirect, $g_RedirectPHPFragment, true);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of symlinks " . count($g_SymLinks));
    
    if (count($g_SymLinks) > 0) {
        $g_SymLinks               = array_slice($g_SymLinks, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['sym_links'] = $g_SymLinks;
        $l_Result .= '<div class="note_vir">' . AI_STR_022 . ' (' . count($g_SymLinks) . ')</div><div class="crit">';
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_SymLinks), true));
        $l_Result .= "</div><div class=\"spacer\"></div>";
    }
    
}

////////////////////////////////////
if (!AI_HOSTER) {
    $l_WarningsNum = count($g_HeuristicDetected) + count($g_HiddenFiles) + count($g_BigFiles) + count($g_PHPCodeInside) + count($g_AdwareList) + count($g_EmptyLink) + count($g_Doorway) + (count($g_WarningPHP[0]) + count($g_WarningPHP[1]) + count($g_SkippedFolders));
    
    if ($l_WarningsNum > 0) {
        $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_026 . "</div>";
    }
    
    stdOut("Building list of adware " . count($g_AdwareList));
    
    if (count($g_AdwareList) > 0) {
        $l_RawReport['adware'] = getRawJson($g_AdwareList, $g_AdwareListFragment);
        $l_Result .= '<div class="note_warn">' . AI_STR_029 . '</div><div class="warn">';
        $l_Result .= printList($g_AdwareList, $g_AdwareListFragment, true);
        $l_PlainResult .= '[ADWARE]' . "\n" . printPlainList($g_AdwareList, $g_AdwareListFragment, true) . "\n";
        $l_Result .= "</div>" . PHP_EOL;        
    }
    
    stdOut("Building list of bigfiles " . count($g_BigFiles));
    $max_size_to_scan = getBytes(MAX_SIZE_TO_SCAN);
    $max_size_to_scan = $max_size_to_scan > 0 ? $max_size_to_scan : getBytes('1m');
    
    if (count($g_BigFiles) > 0) {
        $g_BigFiles               = array_slice($g_BigFiles, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['big_files'] = getRawJson($g_BigFiles);
        $l_Result .= "<div class=\"note_warn\">" . sprintf(AI_STR_038, bytes2Human($max_size_to_scan)) . '</div><div class="warn">';
        $l_Result .= printList($g_BigFiles);
        $l_Result .= "</div>";
        $l_PlainResult .= '[BIG FILES / SKIPPED]' . "\n" . printPlainList($g_BigFiles) . "\n\n";
    }
    
    stdOut("Building list of doorways " . count($g_Doorway));
    
    if ((count($g_Doorway) > 0) && (($defaults['report_mask'] & REPORT_MASK_DOORWAYS) == REPORT_MASK_DOORWAYS)) {
        $g_Doorway              = array_slice($g_Doorway, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['doorway'] = getRawJson($g_Doorway);
        $l_Result .= '<div class="note_warn">' . AI_STR_034 . '</div><div class="warn">';
        $l_Result .= printList($g_Doorway);
        $l_Result .= "</div>" . PHP_EOL;
        
    }
    
    if (count($g_CMS) > 0) {
        $l_RawReport['cms'] = $g_CMS;
        $l_Result .= "<div class=\"note_warn\">" . AI_STR_037 . "<br/>";
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_CMS)));
        $l_Result .= "</div>";
    }
}

if (ICHECK) {
    $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_087 . "</div>";
    
    stdOut("Building list of added files " . count($changes['addedFiles']));
    if (count($changes['addedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_082 . ' (' . count($changes['addedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of modified files " . count($changes['modifiedFiles']));
    if (count($changes['modifiedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_083 . ' (' . count($changes['modifiedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['modifiedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of deleted files " . count($changes['deletedFiles']));
    if (count($changes['deletedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_084 . ' (' . count($changes['deletedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of added dirs " . count($changes['addedDirs']));
    if (count($changes['addedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_085 . ' (' . count($changes['addedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedDirs']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of deleted dirs " . count($changes['deletedDirs']));
    if (count($changes['deletedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_086 . ' (' . count($changes['deletedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedDirs']);
        $l_Result .= "</div>" . PHP_EOL;
    }
}

if (!isCli()) {
    $l_Result .= QCR_ExtractInfo($l_PhpInfoBody[1]);
}


if (function_exists('memory_get_peak_usage')) {
    $l_Template = str_replace("@@MEMORY@@", AI_STR_043 . bytes2Human(memory_get_peak_usage()), $l_Template);
}

$l_Template = str_replace('@@WARN_QUICK@@', ((SCAN_ALL_FILES || $g_SpecificExt) ? '' : AI_STR_045), $l_Template);

if ($l_ShowOffer) {
    $l_Template = str_replace('@@OFFER@@', $l_Offer, $l_Template);
} else {
    $l_Template = str_replace('@@OFFER@@', AI_STR_002, $l_Template);
}

$l_Template = str_replace('@@OFFER2@@', $l_Offer2, $l_Template);

$l_Template = str_replace('@@CAUTION@@', AI_STR_003, $l_Template);

$l_Template = str_replace('@@CREDITS@@', AI_STR_075, $l_Template);

$l_Template = str_replace('@@FOOTER@@', AI_STR_076, $l_Template);

$l_Template = str_replace('@@STAT@@', sprintf(AI_STR_012, $time_taken, date('d-m-Y в H:i:s', floor(START_TIME)), date('d-m-Y в H:i:s')), $l_Template);

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MAIN_CONTENT@@", $l_Result, $l_Template);

if (!isCli()) {
    echo $l_Template;
    exit;
}

if (!defined('REPORT') OR REPORT === '') {
    die2('Report not written.');
}

// write plain text result
if (PLAIN_FILE != '') {
    
    $l_PlainResult = preg_replace('|__AI_LINE1__|smi', '[', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_LINE2__|smi', '] ', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_MARKER__|smi', ' %> ', $l_PlainResult);
    
    if ($l_FH = fopen(PLAIN_FILE, "w")) {
        fputs($l_FH, $l_PlainResult);
        fclose($l_FH);
    }
}

// write json result
if (defined('JSON_FILE')) {
    $res = @json_encode($l_RawReport);
    if ($l_FH = fopen(JSON_FILE, "w")) {
        fputs($l_FH, $res);
        fclose($l_FH);
    }

    if (JSON_STDOUT) {
       echo $res;
    }
}

// write serialized result
if (defined('PHP_FILE')) {
    if ($l_FH = fopen(PHP_FILE, "w")) {
        fputs($l_FH, serialize($l_RawReport));
        fclose($l_FH);
    }
}

$emails = getEmails(REPORT);

if (!$emails) {
    if ($l_FH = fopen($file, "w")) {
        fputs($l_FH, $l_Template);
        fclose($l_FH);
        stdOut("\nReport written to '$file'.");
    } else {
        stdOut("\nCannot create '$file'.");
    }
} else {
    $headers = array(
        'MIME-Version: 1.0',
        'Content-type: text/html; charset=UTF-8',
        'From: ' . ($defaults['email_from'] ? $defaults['email_from'] : 'AI-Bolit@myhost')
    );
    
    for ($i = 0, $size = sizeof($emails); $i < $size; $i++) {
        //$res = @mail($emails[$i], 'AI-Bolit Report ' . date("d/m/Y H:i", time()), $l_Result, implode("\r\n", $headers));
    }
    
    if ($res) {
       stdOut("\nReport sended to " . implode(', ', $emails));
    }
}

$time_taken = microtime(true) - START_TIME;
$time_taken = number_format($time_taken, 5);

stdOut("Scanning complete! Time taken: " . seconds2Human($time_taken));

if (DEBUG_PERFORMANCE) {
    $keys = array_keys($g_RegExpStat);
    for ($i = 0; $i < count($keys); $i++) {
        $g_RegExpStat[$keys[$i]] = round($g_RegExpStat[$keys[$i]] * 1000000);
    }
    
    arsort($g_RegExpStat);
    
    foreach ($g_RegExpStat as $r => $v) {
        echo $v . "\t\t" . $r . "\n";
    }
    
    die();
}

stdOut("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
stdOut("Attention! DO NOT LEAVE either ai-bolit.php or AI-BOLIT-REPORT-<xxxx>-<yy>.html \nfile on server. COPY it locally then REMOVE from server. ");
stdOut("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

if (isset($options['quarantine'])) {
    Quarantine();
}

if (isset($options['cmd'])) {
    stdOut("Run \"{$options['cmd']}\" ");
    system($options['cmd']);
}

QCR_Debug();

# exit with code

$l_EC1 = count($g_CriticalPHP);
$l_EC2 = count($g_CriticalJS) + count($g_Phishing) + count($g_WarningPHP[0]) + count($g_WarningPHP[1]);
$code  = 0;

if ($l_EC1 > 0) {
    $code = 2;
} else {
    if ($l_EC2 > 0) {
        $code = 1;
    }
}

$stat = array(
    'php_malware' => count($g_CriticalPHP),
    'js_malware' => count($g_CriticalJS),
    'phishing' => count($g_Phishing)
);

if (function_exists('aibolit_onComplete')) {
    aibolit_onComplete($code, $stat);
}

stdOut('Exit code ' . $code);
exit($code);

############################################# END ###############################################

function Quarantine() {
    if (!file_exists(DOUBLECHECK_FILE)) {
        return;
    }
    
    $g_QuarantinePass = 'aibolit';
    
    $archive  = "AI-QUARANTINE-" . rand(100000, 999999) . ".zip";
    $infoFile = substr($archive, 0, -3) . "txt";
    $report   = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE;
    
    
    foreach (file(DOUBLECHECK_FILE) as $file) {
        $file = trim($file);
        if (!is_file($file))
            continue;
        
        $lStat = stat($file);
        
        // skip files over 300KB
        if ($lStat['size'] > 300 * 1024)
            continue;
        
        // http://www.askapache.com/security/chmod-stat.html
        $p    = $lStat['mode'];
        $perm = '-';
        $perm .= (($p & 0x0100) ? 'r' : '-') . (($p & 0x0080) ? 'w' : '-');
        $perm .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-'));
        $perm .= (($p & 0x0020) ? 'r' : '-') . (($p & 0x0010) ? 'w' : '-');
        $perm .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-'));
        $perm .= (($p & 0x0004) ? 'r' : '-') . (($p & 0x0002) ? 'w' : '-');
        $perm .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-'));
        
        $owner = (function_exists('posix_getpwuid')) ? @posix_getpwuid($lStat['uid']) : array(
            'name' => $lStat['uid']
        );
        $group = (function_exists('posix_getgrgid')) ? @posix_getgrgid($lStat['gid']) : array(
            'name' => $lStat['uid']
        );
        
        $inf['permission'][] = $perm;
        $inf['owner'][]      = $owner['name'];
        $inf['group'][]      = $group['name'];
        $inf['size'][]       = $lStat['size'] > 0 ? bytes2Human($lStat['size']) : '-';
        $inf['ctime'][]      = $lStat['ctime'] > 0 ? date("d/m/Y H:i:s", $lStat['ctime']) : '-';
        $inf['mtime'][]      = $lStat['mtime'] > 0 ? date("d/m/Y H:i:s", $lStat['mtime']) : '-';
        $files[]             = strpos($file, './') === 0 ? substr($file, 2) : $file;
    }
    
    // get config files for cleaning
    $configFilesRegex = 'config(uration|\.in[ic])?\.php$|dbconn\.php$';
    $configFiles      = preg_grep("~$configFilesRegex~", $files);
    
    // get columns width
    $width = array();
    foreach (array_keys($inf) as $k) {
        $width[$k] = strlen($k);
        for ($i = 0; $i < count($inf[$k]); ++$i) {
            $len = strlen($inf[$k][$i]);
            if ($len > $width[$k])
                $width[$k] = $len;
        }
    }
    
    // headings of columns
    $info = '';
    foreach (array_keys($inf) as $k) {
        $info .= str_pad($k, $width[$k], ' ', STR_PAD_LEFT) . ' ';
    }
    $info .= "name\n";
    
    for ($i = 0; $i < count($files); ++$i) {
        foreach (array_keys($inf) as $k) {
            $info .= str_pad($inf[$k][$i], $width[$k], ' ', STR_PAD_LEFT) . ' ';
        }
        $info .= $files[$i] . "\n";
    }
    unset($inf, $width);
    
    exec("zip -v 2>&1", $output, $code);
    
    if ($code == 0) {
        $filter = '';
        if ($configFiles && exec("grep -V 2>&1", $output, $code) && $code == 0) {
            $filter = "|grep -v -E '$configFilesRegex'";
        }
        
        exec("cat AI-BOLIT-DOUBLECHECK.php $filter |zip -@ --password $g_QuarantinePass $archive", $output, $code);
        if ($code == 0) {
            file_put_contents($infoFile, $info);
            $m = array();
            if (!empty($filter)) {
                foreach ($configFiles as $file) {
                    $tmp  = file_get_contents($file);
                    // remove  passwords
                    $tmp  = preg_replace('~^.*?pass.*~im', '', $tmp);
                    // new file name
                    $file = preg_replace('~.*/~', '', $file) . '-' . rand(100000, 999999);
                    file_put_contents($file, $tmp);
                    $m[] = $file;
                }
            }
            
            exec("zip -j --password $g_QuarantinePass $archive $infoFile $report " . DOUBLECHECK_FILE . ' ' . implode(' ', $m));
            stdOut("\nCreate archive '" . realpath($archive) . "'");
            stdOut("This archive have password '$g_QuarantinePass'");
            foreach ($m as $file)
                unlink($file);
            unlink($infoFile);
            return;
        }
    }
    
    $zip = new ZipArchive;
    
    if ($zip->open($archive, ZIPARCHIVE::CREATE | ZIPARCHIVE::OVERWRITE) === false) {
        stdOut("Cannot create '$archive'.");
        return;
    }
    
    foreach ($files as $file) {
        if (in_array($file, $configFiles)) {
            $tmp = file_get_contents($file);
            // remove  passwords
            $tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
            $zip->addFromString($file, $tmp);
        } else {
            $zip->addFile($file);
        }
    }
    $zip->addFile(DOUBLECHECK_FILE, DOUBLECHECK_FILE);
    $zip->addFile($report, REPORT_FILE);
    $zip->addFromString($infoFile, $info);
    $zip->close();
    
    stdOut("\nCreate archive '" . realpath($archive) . "'.");
    stdOut("This archive has no password!");
}



///////////////////////////////////////////////////////////////////////////
function QCR_IntegrityCheck($l_RootDir) {
    global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, $defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SuspiciousFiles, $l_SkipSample;
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';
    
    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $g_Counter - 1;
    
    QCR_Debug('Check ' . $l_RootDir);
    
    if ($l_DIRH = @opendir($l_RootDir)) {
        while (($l_FileName = readdir($l_DIRH)) !== false) {
            if ($l_FileName == '.' || $l_FileName == '..')
                continue;
            
            $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;
            
            $l_Type  = filetype($l_FileName);
            $l_IsDir = ($l_Type == "dir");
            if ($l_Type == "link") {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else if ($l_Type != "file" && (!$l_IsDir)) {
                $g_UnixExec[] = $l_FileName;
                continue;
            }
            
            $l_Ext = substr($l_FileName, strrpos($l_FileName, '.') + 1);
            
            $l_NeedToScan = true;
            $l_Ext2       = substr(strstr(basename($l_FileName), '.'), 1);
            if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                $l_NeedToScan = false;
            }
            
            // if folder in ignore list
            $l_Skip = false;
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                    if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                        $l_SkipSample[] = $g_DirIgnoreList[$dr];
                    } else {
                        $l_Skip       = true;
                        $l_NeedToScan = false;
                    }
                }
            }
            
            if (getRelativePath($l_FileName) == "./" . INTEGRITY_DB_FILE)
                $l_NeedToScan = false;
            
            if ($l_IsDir) {
                // skip on ignore
                if ($l_Skip) {
                    $g_SkippedFolders[] = $l_FileName;
                    continue;
                }
                
                $l_BaseName = basename($l_FileName);
                
                $l_DirCounter++;
                
                $g_Counter++;
                $g_FoundTotalDirs++;
                
                QCR_IntegrityCheck($l_FileName);
                
            } else {
                if ($l_NeedToScan) {
                    $g_FoundTotalFiles++;
                    $g_Counter++;
                }
            }
            
            if (!$l_NeedToScan)
                continue;
            
            if (IMAKE) {
                write_integrity_db_file($l_FileName);
                continue;
            }
            
            // ICHECK
            // skip if known and not modified.
            if (icheck($l_FileName))
                continue;
            
            $l_Buffer .= getRelativePath($l_FileName);
            $l_Buffer .= $l_IsDir ? DIR_SEPARATOR . "\n" : "\n";
            
            if (strlen($l_Buffer) > 32000) {
                file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
                $l_Buffer = '';
            }
            
        }
        
        closedir($l_DIRH);
    }
    
    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }
    
    if (($l_RootDir == ROOT_PATH)) {
        write_integrity_db_file();
    }
    
}


function getRelativePath($l_FileName) {
    return "./" . substr($l_FileName, strlen(ROOT_PATH) + 1) . (is_dir($l_FileName) ? DIR_SEPARATOR : '');
}

/**
 *
 * @return true if known and not modified
 */
function icheck($l_FileName) {
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';
    static $l_status = array('modified' => 'modified', 'added' => 'added');
    
    $l_RelativePath = getRelativePath($l_FileName);
    $l_known        = isset($g_IntegrityDB[$l_RelativePath]);
    
    if (is_dir($l_FileName)) {
        if ($l_known) {
            unset($g_IntegrityDB[$l_RelativePath]);
        } else {
            $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        }
        return $l_known;
    }
    
    if ($l_known == false) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        return false;
    }
    
    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
    
    if ($g_IntegrityDB[$l_RelativePath] != $hash) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['modified'];
        return false;
    }
    
    unset($g_IntegrityDB[$l_RelativePath]);
    return true;
}

function write_integrity_db_file($l_FileName = '') {
    static $l_Buffer = '';
    
    if (empty($l_FileName)) {
        empty($l_Buffer) or file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
        return;
    }
    
    $l_RelativePath = getRelativePath($l_FileName);
    
    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
    
    $l_Buffer .= "$l_RelativePath|$hash\n";
    
    if (strlen($l_Buffer) > 32000) {
        file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
    }
}

function load_integrity_db() {
    global $g_IntegrityDB;
    file_exists(INTEGRITY_DB_FILE) or die2('Not found ' . INTEGRITY_DB_FILE);
    
    $s_file = new SplFileObject('compress.zlib://' . INTEGRITY_DB_FILE);
    $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
    
    foreach ($s_file as $line) {
        $i = strrpos($line, '|');
        if (!$i)
            continue;
        $g_IntegrityDB[substr($line, 0, $i)] = substr($line, $i + 1);
    }
    
    $s_file = null;
}


function getStdin()
{
    $stdin  = '';
    $f      = @fopen('php://stdin', 'r');
    while($line = fgets($f)) 
    {
        $stdin .= $line;
    }
    fclose($f);
    return $stdin;
}

function OptimizeSignatures() {
    global $g_DBShe, $g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe;
    global $g_JSVirSig, $gX_JSVirSig;
    global $g_AdwareSig;
    global $g_PhishingSig;
    global $g_ExceptFlex, $g_SusDBPrio, $g_SusDB;
    
    (AI_EXPERT == 2) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe));
    (AI_EXPERT == 1) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe));
    $gX_FlexDBShe = $gXX_FlexDBShe = array();
    
    (AI_EXPERT == 2) && ($g_JSVirSig = array_merge($g_JSVirSig, $gX_JSVirSig));
    $gX_JSVirSig = array();
    
    $count = count($g_FlexDBShe);
    
    for ($i = 0; $i < $count; $i++) {
        if ($g_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
            $g_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
        if ($g_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
            $g_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
        if ($g_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
            $g_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';
        
        $g_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $g_FlexDBShe[$i]);
        
        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
    }
    
    optSig($g_FlexDBShe);
    
    optSig($g_JSVirSig);
    
    
    
    //optSig($g_SusDBPrio);
    //optSig($g_ExceptFlex);
    
    // convert exception rules
    $cnt = count($g_ExceptFlex);
    for ($i = 0; $i < $cnt; $i++) {
        $g_ExceptFlex[$i] = trim(UnwrapObfu($g_ExceptFlex[$i]));
        if (!strlen($g_ExceptFlex[$i]))
            unset($g_ExceptFlex[$i]);
    }
    
    $g_ExceptFlex = array_values($g_ExceptFlex);
}

function optSig(&$sigs) {
    $sigs = array_unique($sigs);
    
    // Add SigId
    foreach ($sigs as &$s) {
        $s .= '(?<X' . myCheckSum($s) . '>)';
    }
    unset($s);
    
    $fix = array(
        '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
        'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
        '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
        '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
    );
    
    $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
    
    $fix = array(
        '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
        '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
    );
    
    $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);
    
    optSigCheck($sigs);
    
    $tmp = array();
    foreach ($sigs as $i => $s) {
        if (!preg_match('#^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$#', $s)) {
            unset($sigs[$i]);
            $tmp[] = $s;
        }
    }
    
    usort($sigs, 'strcasecmp');
    $txt = implode("\n", $sigs);
    
    for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
        $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'optMergePrefixes', $txt);
    }
    
    $sigs = array_merge(explode("\n", $txt), $tmp);
    
    optSigCheck($sigs);
}

function optMergePrefixes($m) {
    $limit = 8000;
    
    $prefix     = $m[1];
    $prefix_len = strlen($prefix);
    
    $len = $prefix_len;
    $r   = array();
    
    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {
        
        if (strlen($line) > $limit) {
            $r[] = $line;
            continue;
        }
        
        $s = substr($line, $prefix_len);
        $len += strlen($s);
        if ($len > $limit) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
            $suffixes = array();
            $len      = $prefix_len + strlen($s);
        }
        $suffixes[] = $s;
    }
    
    if (!empty($suffixes)) {
        if (count($suffixes) == 1) {
            $r[] = $prefix . $suffixes[0];
        } else {
            $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
        }
    }
    
    return implode("\n", $r);
}

function optMergePrefixes_Old($m) {
    $prefix     = $m[1];
    $prefix_len = strlen($prefix);
    
    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {
        $suffixes[] = substr($line, $prefix_len);
    }
    
    return $prefix . '(?:' . implode('|', $suffixes) . ')';
}

/*
 * Checking errors in pattern
 */
function optSigCheck(&$sigs) {
    $result = true;
    
    foreach ($sigs as $k => $sig) {
        if (trim($sig) == "") {
            if (DEBUG_MODE) {
                echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
        
        if (@preg_match('#' . $sig . '#smiS', '') === false) {
            $error = error_get_last();
            if (DEBUG_MODE) {
                echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
    }
    
    return $result;
}

function _hash_($text) {
    static $r;
    
    if (empty($r)) {
        for ($i = 0; $i < 256; $i++) {
            if ($i < 33 OR $i > 127)
                $r[chr($i)] = '';
        }
    }
    
    return sha1(strtr($text, $r));
}

function check_whitelist($list, &$snum) {
    global $defaults;

    if (empty($list))
        return array();
    
    $file = dirname(__FILE__) . '/AIBOLIT-WHITELIST.db';
    if (isset($defaults['avdb'])) {
       $file = dirname($defaults['avdb']) . '/AIBOLIT-WHITELIST.db';
    }

    if (!file_exists($file)) {
        return array();
    }
    
    $snum = max(0, @filesize($file) - 1024) / 20;
    stdOut("\nLoaded " . ceil($snum) . " known files from " . $file . "\n");
    
    sort($list);
    
    $hash = reset($list);
    
    $fp = @fopen($file, 'rb');
    
    if (false === $fp)
        return array();
    
    $header = unpack('V256', fread($fp, 1024));
    
    $result = array();
    
    foreach ($header as $chunk_id => $chunk_size) {
        if ($chunk_size > 0) {
            $str = fread($fp, $chunk_size);
            
            do {
                $raw = pack("H*", $hash);
                $id  = ord($raw[0]) + 1;
                
                if ($chunk_id == $id AND binarySearch($str, $raw)) {
                    $result[] = $hash;
                }
                
            } while ($chunk_id >= $id AND $hash = next($list));
            
            if ($hash === false)
                break;
        }
    }
    
    fclose($fp);
    
    return $result;
}


function binarySearch($str, $item) {
    $item_size = strlen($item);
    if ($item_size == 0)
        return false;
    
    $first = 0;
    
    $last = floor(strlen($str) / $item_size);
    
    while ($first < $last) {
        $mid = $first + (($last - $first) >> 1);
        $b   = substr($str, $mid * $item_size, $item_size);
        if (strcmp($item, $b) <= 0)
            $last = $mid;
        else
            $first = $mid + 1;
    }
    
    $b = substr($str, $last * $item_size, $item_size);
    if ($b == $item) {
        return true;
    } else {
        return false;
    }
}

function getSigId($l_Found) {
    foreach ($l_Found as $key => &$v) {
        if (is_string($key) AND $v[1] != -1 AND strlen($key) == 9) {
            return substr($key, 1);
        }
    }
    
    return null;
}

function die2($str) {
    if (function_exists('aibolit_onFatalError')) {
        aibolit_onFatalError($str);
    }
    die($str);
}

function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType) {
    global $g_DeMapper;
    
    if ($l_DeobfType != '') {
        if (DEBUG_MODE) {
            stdOut("\n-----------------------------------------------------------------------------\n");
            stdOut("[DEBUG]" . $l_Filename . "\n");
            var_dump(getFragment($l_Unwrapped, $l_Pos));
            stdOut("\n...... $l_DeobfType ...........\n");
            var_dump($l_Unwrapped);
            stdOut("\n");
        }
        
        switch ($l_DeobfType) {
            case '_GLOBALS_':
                foreach ($g_DeMapper as $fkey => $fvalue) {
                    if (DEBUG_MODE) {
                        stdOut("[$fkey] => [$fvalue]\n");
                    }
                    
                    if ((strpos($l_Filename, $fkey) !== false) && (strpos($l_Unwrapped, $fvalue) !== false)) {
                        if (DEBUG_MODE) {
                            stdOut("\n[DEBUG] *** SKIP: False Positive\n");
                        }
                        
                        return true;
                    }
                }
                break;
        }
        
        
        return false;
    }
}

$full_code = '';

function deobfuscate_bitrix($str) {
    $res      = $str;
    $funclist = array();
    $strlist  = array();
    $res      = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
    $res      = preg_replace_callback('~(?:min|max)\(\s*\d+[\,\|\s\|+\|\-\|\*\|\/][\d\s\.\,\+\-\*\/]+\)~ms', "calc", $res);
    $res = preg_replace_callback('|(round\((.+?)\))|smi', function($matches) {
        return round($matches[2]);
    }, $res);
    $res = preg_replace_callback('|base64_decode\(["\'](.*?)["\']\)|smi', function($matches) {
        return "'" . base64_decode($matches[1]) . "'";
    }, $res);
    
    $res = preg_replace_callback('|["\'](.*?)["\']|sm', function($matches) {
        $temp = base64_decode($matches[1]);
        if (base64_encode($temp) === $matches[1] && preg_match('#^[ -~]*$#', $temp)) {
            return "'" . $temp . "'";
        } else {
            return "'" . $matches[1] . "'";
        }
    }, $res);
    
    
    if (preg_match_all('|\$GLOBALS\[\'(.+?)\'\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $varname            = $found[1];
            $funclist[$varname] = explode(',', $found[2]);
            $funclist[$varname] = array_map(function($value) {
                return trim($value, "'");
            }, $funclist[$varname]);
            
            $res = preg_replace_callback('|\$GLOBALS\[\'' . $varname . '\'\]\[(\d+)\]|smi', function($matches) use ($varname, $funclist) {
                return $funclist[$varname][$matches[1]];
            }, $res);
        }
    }
    
    
    if (preg_match_all('|function\s*(\w{1,60})\(\$\w+\){\$\w{1,60}\s*=\s*Array\((.{1,30000}?)\);[^}]+}|smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $strlist = explode(',', $found[2]);
            $res = preg_replace_callback('|' . $found[1] . '\((\d+)\)|smi', function($matches) use ($strlist) {
                return $strlist[$matches[1]];
            }, $res);
            
            //$res = preg_replace('~' . quotemeta(str_replace('~', '\\~', $found[0])) . '~smi', '', $res);
        }
    }
    
    $res = preg_replace('~<\?(php)?\s*\?>~smi', '', $res);
    if (preg_match_all('~<\?\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3=array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $strlist = explode("',", $found[5]);
            $res = preg_replace_callback('|' . $found[1] . '\((\d+)\)|sm', function($matches) use ($strlist) {
                return $strlist[$matches[1]] . "'";
            }, $res);
            
        }
    }
    
    return $res;
}

function calc($expr) {
    if (is_array($expr))
        $expr = $expr[0];
    preg_match('~(min|max)?\(([^\)]+)\)~msi', $expr, $expr_arr);
    if ($expr_arr[1] == 'min' || $expr_arr[1] == 'max')
        return $expr_arr[1](explode(',', $expr_arr[2]));
    else {
        preg_match_all('~([\d\.]+)([\*\/\-\+])?~', $expr, $expr_arr);
        if (in_array('*', $expr_arr[2]) !== false) {
            $pos  = array_search('*', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] * $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "*" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('/', $expr_arr[2]) !== false) {
            $pos  = array_search('/', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] / $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "/" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('-', $expr_arr[2]) !== false) {
            $pos  = array_search('-', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] - $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "-" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('+', $expr_arr[2]) !== false) {
            $pos  = array_search('+', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] + $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "+" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } else {
            return $expr;
        }
        
        return $expr;
    }
}

function my_eval($matches) {
    $string = $matches[0];
    $string = substr($string, 5, strlen($string) - 7);
    return decode($string);
}

function decode($string, $level = 0) {
    if (trim($string) == '')
        return '';
    if ($level > 100)
        return '';
    
    if (($string[0] == '\'') || ($string[0] == '"')) {
        return substr($string, 1, strlen($string) - 2); //
    } elseif ($string[0] == '$') {
        global $full_code;
        $string = str_replace(")", "", $string);
        preg_match_all('~\\' . $string . '\s*=\s*(\'|")([^"\']+)(\'|")~msi', $full_code, $matches);
        return $matches[2][0]; //
    } else {
        $pos      = strpos($string, '(');
        $function = substr($string, 0, $pos);
        
        $arg = decode(substr($string, $pos + 1), $level + 1);
        if (strtolower($function) == 'base64_decode')
            return @base64_decode($arg);
        else if (strtolower($function) == 'gzinflate')
            return @gzinflate($arg);
        else if (strtolower($function) == 'gzuncompress')
            return @gzuncompress($arg);
        else if (strtolower($function) == 'strrev')
            return @strrev($arg);
        else if (strtolower($function) == 'str_rot13')
            return @str_rot13($arg);
        else
            return $arg;
    }
}

function deobfuscate_eval($str) {
    global $full_code;
    $res = preg_replace_callback('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress).*?\);~msi', "my_eval", $str);
    return str_replace($str, $res, $full_code);
}

function getEvalCode($string) {
    preg_match("/eval\((.*?)\);/", $string, $matches);
    return (empty($matches)) ? '' : end($matches);
}

function getTextInsideQuotes($string) {
    if (preg_match_all('/("(.*?)")/', $string, $matches))
        return @end(end($matches));
    elseif (preg_match_all('/(\'(.*?)\')/', $string, $matches))
        return @end(end($matches));
    else
        return '';
}

function deobfuscate_lockit($str) {
    $obfPHP        = $str;
    $phpcode       = base64_decode(getTextInsideQuotes(getEvalCode($obfPHP)));
    $hexvalues     = getHexValues($phpcode);
    $tmp_point     = getHexValues($obfPHP);
    $pointer1      = hexdec($tmp_point[0]);
    $pointer2      = hexdec($hexvalues[0]);
    $pointer3      = hexdec($hexvalues[1]);
    $needles       = getNeedles($phpcode);
    $needle        = $needles[count($needles) - 2];
    $before_needle = end($needles);
    
    
    $phpcode = base64_decode(strtr(substr($obfPHP, $pointer2 + $pointer3, $pointer1), $needle, $before_needle));
    return "<?php {$phpcode} ?>";
}


function getNeedles($string) {
    preg_match_all("/'(.*?)'/", $string, $matches);
    
    return (empty($matches)) ? array() : $matches[1];
}

function getHexValues($string) {
    preg_match_all('/0x[a-fA-F0-9]{1,8}/', $string, $matches);
    return (empty($matches)) ? array() : $matches[0];
}

function deobfuscate_als($str) {
    preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str, $layer1);
    preg_match('~\$[O0]+=(\$[O0]+\()+\$[O0]+,[0-9a-fx]+\),\'([^\']+)\',\'([^\']+)\'\)\);eval\(~msi', base64_decode($layer1[1]), $layer2);
    $res = explode("?>", $str);
    if (strlen(end($res)) > 0) {
        $res = substr(end($res), 380);
        $res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
    }
    return "<?php {$res} ?>";
}

function deobfuscate_byterun($str) {
    global $full_code;
    preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
    $res = base64_decode($matches[1]);
    $res = strtr($res, '123456aouie', 'aouie123456');
    return "<?php " . str_replace($matches[0], $res, $full_code) . " ?>";
}

function deobfuscate_urldecode($str) {
    preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str, $matches);
    $alph  = urldecode($matches[2]);
    $funcs = $matches[3];
    for ($i = 0; $i < strlen($alph); $i++) {
        $funcs = str_replace($matches[1] . '{' . $i . '}.', $alph[$i], $funcs);
        $funcs = str_replace($matches[1] . '{' . $i . '}', $alph[$i], $funcs);
    }
    
    $str   = str_replace($matches[3], $funcs, $str);
    $funcs = explode(';', $funcs);
    foreach ($funcs as $func) {
        $func_arr = explode("=", $func);
        if (count($func_arr) == 2) {
            $func_arr[0] = str_replace('$', '', $func_arr[0]);
            $str         = str_replace('${"GLOBALS"}["' . $func_arr[0] . '"]', $func_arr[1], $str);
        }
    }
    
    return $str;
}


function formatPHP($string) {
    $string = str_replace('<?php', '', $string);
    $string = str_replace('?>', '', $string);
    $string = str_replace(PHP_EOL, "", $string);
    $string = str_replace(";", ";\n", $string);
    return $string;
}

function deobfuscate_fopo($str) {
    $phpcode = formatPHP($str);
    $phpcode = base64_decode(getTextInsideQuotes(getEvalCode($phpcode)));
    @$phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(end(explode(':', $phpcode))))));
    $old = '';
    while (($old != $phpcode) && (strlen(strstr($phpcode, '@eval($')) > 0)) {
        $old   = $phpcode;
        $funcs = explode(';', $phpcode);
        if (count($funcs) == 5)
            $phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(getEvalCode($phpcode)))));
        else if (count($funcs) == 4)
            $phpcode = gzinflate(base64_decode(getTextInsideQuotes(getEvalCode($phpcode))));
    }
    
    return substr($phpcode, 2);
}

function getObfuscateType($str) {
    if (preg_match('~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~function\s*_+\d+\s*\(\s*\$i\s*\)\s*{\s*\$a\s*=\s*Array~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str))
        return "ALS-Fullsite";
    if (preg_match('~\$[O0]*=urldecode\(\'%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64\'\);\s*\$GLOBALS\[\'[O0]*\'\]=\$[O0]*~msi', $str))
        return "LockIt!";
    if (preg_match('~\$\w+="(\\\x?[0-9a-f]+){13}";@eval\(\$\w+\(~msi', $str))
        return "FOPO";
    if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms', $str))
        return "ByteRun";
    if (preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str))
        return "urldecode_globals";
    if (preg_match('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress)~msi', $str))
        return "eval";
}

function deobfuscate($str) {
    switch (getObfuscateType($str)) {
        case '_GLOBALS_':
            $str = deobfuscate_bitrix(($str));
            break;
        case 'eval':
            $str = deobfuscate_eval(($str));
            break;
        case 'ALS-Fullsite':
            $str = deobfuscate_als(($str));
            break;
        case 'LockIt!':
            $str = deobfuscate_lockit($str);
            break;
        case 'FOPO':
            $str = deobfuscate_fopo(($str));
            break;
        case 'ByteRun':
            $str = deobfuscate_byterun(($str));
            break;
        case 'urldecode_globals':
            $str = deobfuscate_urldecode(($str));
            break;
    }
    
    return $str;
}

function convertToUTF8($text)
{
    if (function_exists('mb_convert_encoding')) {
       $text = @mb_convert_encoding($text, 'utf-8', 'auto');
       $text = @mb_convert_encoding($text, 'UTF-8', 'UTF-8');
    }

    return $text;
}
