;; =========================================================
;; КУРСОВАЯ РАБОТА: чтение и распаковка файла формата ZIP
;; =========================================================

(defpackage :zip-parser-memory
  (:use :cl)
  (:export :analyze-zip
           :print-zip-details-complete
           :read-zip-file-into-array))

(in-package :zip-parser-memory)

;; ---------------------------------------------------------
;; 0. КОНСТАНТЫ (NO MAGIC NUMBERS)
;; ---------------------------------------------------------

(defconstant +sig-local-file-header+ #x04034B50 "Сигнатура заголовка локального файла")

(defconstant +sig-central-directory+ #x02014B50 "Сигнатура записи в центральном каталоге")

(defconstant +sig-eocd+              #x06054B50 "Сигнатура конца центрального каталога (EOCD)")

;; ---------------------------------------------------------
;; 1. СИСТЕМА ОШИБОК (CUSTOM CONDITIONS)
;; ---------------------------------------------------------

(define-condition zip-error (error)
  ((message :initarg :message
            :reader zip-error-message))
  (:report (lambda (condition stream)
             (format stream "ZIP Error: ~A"
                     (zip-error-message condition)))))

(define-condition zip-signature-error (zip-error)
  ((expected :initarg :expected
             :reader expected-sig)
   (actual   :initarg :actual
             :reader actual-sig))
  (:report (lambda (c s)
             (format s "Invalid Signature. Expected: 0x~X, Got: 0x~X"
                     (expected-sig c)
                     (actual-sig c)))))

;; ---------------------------------------------------------
;; 2. СТРУКТУРЫ ДАННЫХ
;; ---------------------------------------------------------

;; Структура потока чтения (наш аналог FILE* над памятью)
(defstruct z-stream
  buffer    ; Массив байтов (куда загружен весь файл)
  pos       ; Текущая позиция (курсор)
  len)      ; Длина массива

;; Структура End of Central Directory (EOCD)
(defstruct zip-eocd
  disk-number        ; Номер диска, содержащего EOCD (U2)
  cd-disk            ; Номер диска, на котором начинается Central Directory (U2)
  disk-entries       ; Количество записей в CD на этом диске (U2)
  total-entries      ; Общее количество записей в CD (U2)
  cd-size            ; Размер Центрального Каталога в байтах (U4)
  cd-offset          ; Смещение Центрального Каталога относительно начала архива (U4)
  comment-len        ; Длина комментария (U2)
  comment)           ; Комментарий архива (строка)

;; Структура заголовка файла (из Central Directory)
(defstruct zip-entry
  version-made-by      ; Версия программы, создавшей запись (U2)
  version-needed       ; Минимальная версия для извлечения (U2)
  general-purpose-flag ; Общие битовые флаги (U2)
  compression-method   ; Метод сжатия (0=Stored, 8=Deflate и т.д.) (U2)
  last-mod-time        ; Время модификации DOS (U2)
  last-mod-date        ; Дата модификации DOS (U2)
  crc32                ; Контрольная сумма CRC-32 (U4)
  compressed-size      ; Сжатый размер (U4)
  uncompressed-size    ; Исходный размер (U4)
  filename-length      ; Длина имени файла (U2)
  extra-field-length   ; Длина доп. поля (U2)
  file-comment-length  ; Длина комментария файла (U2)
  disk-number-start    ; Номер диска, на котором начинается файл (U2)
  internal-attributes  ; Внутренние атрибуты файла (U2)
  external-attributes  ; Внешние атрибуты файла (U4)
  local-header-offset  ; Смещение Local File Header (U4)
  
  ;; Поля переменной длины
  filename             ; Имя файла (строка)
  extra-field          ; Дополнительные поля (строка)
  comment)             ; Комментарий файла (строка)

;; Главная структура архива
(defstruct zip-archive
  file-path
  eocd-info
  files)

;; ---------------------------------------------------------
;; 3. ГЛОБАЛЬНЫЕ/СПЕЦИАЛЬНЫЕ ПЕРЕМЕННЫЕ
;; ---------------------------------------------------------

(defvar *crc32-table* nil
  "Таблица для быстрой проверки CRC32 (целостности файлов)")

(defvar *my-result* nil
  "Хранит результат последнего анализа ZIP-архива")

;;таблица флагов
(defparameter *zip-general-purpose-flags*
  '((0  "Зашифрован")
    (1  "Оптимизация сжатия: максимальная")
    (2  "Оптимизация сжатия: быстрая")
    (3  "Используется Data Descriptor")
    (6  "Strong Encryption")
    (11 "Имена файлов в UTF-8")
    (13 "Скрытые значения в заголовке")))


;; ---------------------------------------------------------
;; 4. НИЗКОУРОВНЕВОЕ ЧТЕНИЕ
;; ---------------------------------------------------------

(defvar *crc32-table*
  (let ((table (make-array 256
                           :element-type '(unsigned-byte 32))))
    (dotimes (i 256)
      (let ((c i))
        (dotimes (j 8)
          (if (logbitp 0 c)
              (setf c (logxor #xEDB88320 (ash c -1)))
              (setf c (ash c -1))))
        (setf (aref table i) c)))
    table))

(defun calculate-crc32 (bytes)
  "Считает контрольную сумму для массива байтов."
  (let ((crc #xFFFFFFFF))
    (loop for byte across bytes do
      (setf crc (logxor (aref *crc32-table*
                              (logand (logxor crc byte) #xFF))
                        (ash crc -8))))
    (logxor crc #xFFFFFFFF)))

(defun z-seek (stream offset origin)
  "Перемещает курсор (pos) внутри буфера stream с проверкой границ."
  (let ((target 0))
    (case origin
      (:set (setf target offset))
      (:cur (setf target (+ (z-stream-pos stream) offset)))
      (:end (setf target (+ (z-stream-len stream) offset))))
    
    ;; Проверка границ для безопасности
    (when (or (< target 0) (> target (z-stream-len stream)))
      (error 'zip-error
             :message (format nil "Seek out of bounds: ~A" target)))
    
    (setf (z-stream-pos stream) target)
    target))

(defun z-tell (stream)
  "Возвращает текущую позицию курсора."
  (z-stream-pos stream))

(defun z-read-byte (stream)
  "Читает 1 байт и сдвигает курсор."
  (let ((pos (z-stream-pos stream))
        (arr (z-stream-buffer stream)))
    (if (< pos (z-stream-len stream))
        (prog1 (aref arr pos)
          (incf (z-stream-pos stream)))
        (error 'zip-error :message "End of stream reached"))))

;; Макрос для генерации функций чтения чисел (Little Endian)
(defmacro def-read-le (name bytes)
  `(defun ,name (stream)
     (let ((result 0))
       (dotimes (i ,bytes)
         (setf result (logior result
                              (ash (z-read-byte stream)
                                   (* i 8)))))
       result)))

(def-read-le z-read-u2 2)
(def-read-le z-read-u4 4)

(defun z-read-string (stream length)
  "Читает строку заданной длины (ASCII)."
  (if (<= length 0)
      ""
      (let ((str (make-string length))
            (pos (z-stream-pos stream))
            (arr (z-stream-buffer stream)))
        (dotimes (i length)
          (setf (char str i)
                (code-char (aref arr (+ pos i)))))
        (z-seek stream length :cur)
        str)))

(defun z-read-byte-array (stream length)
  "Читает массив байтов заданной длины."
  (let ((arr (make-array length
                         :element-type '(unsigned-byte 8)))
        (src (z-stream-buffer stream))
        (pos (z-stream-pos stream)))
    (dotimes (i length)
      (setf (aref arr i)
            (aref src (+ pos i))))
    (z-seek stream length :cur)
    arr))

;; ---------------------------------------------------------
;; 5. ЛОГИКА ПАРСИНГА
;; ---------------------------------------------------------

(defun find-eocd (stream)
  "Ищет сигнатуру EOCD, сканируя с конца буфера."
  (loop for offset from -22 downto (- -22 65536) do
       (let ((pos (z-seek stream offset :end)))
         (when (<= pos 0) (return nil))
         (let ((sig (z-read-u4 stream)))
           (when (= sig +sig-eocd+)
             (z-seek stream -4 :cur)
             (return (z-tell stream)))
           (z-seek stream -7 :cur)))))

(defun parse-eocd (stream)
  "Читает структуру EOCD."
  (let ((sig (z-read-u4 stream)))
    (unless (= sig +sig-eocd+)
      (error 'zip-signature-error
             :expected +sig-eocd+
             :actual sig)))
  
  (let* ((disk-num (z-read-u2 stream))
         (cd-disk (z-read-u2 stream))
         (disk-entries (z-read-u2 stream))
         (total-entries (z-read-u2 stream))
         (cd-size (z-read-u4 stream))
         (cd-offset (z-read-u4 stream))
         (comment-len (z-read-u2 stream))
         (comment (z-read-string stream comment-len)))
    
    (make-zip-eocd 
     :disk-number disk-num
     :cd-disk cd-disk          
     :disk-entries disk-entries      
     :total-entries total-entries
     :cd-size cd-size
     :cd-offset cd-offset
     :comment-len comment-len          
     :comment comment)))

(defun parse-central-directory (stream eocd)
  "Читает центральный каталог, возвращает список структур zip-entry."
  (z-seek stream (zip-eocd-cd-offset eocd) :set)
  
  (let ((entries '()))
    (dotimes (i (zip-eocd-total-entries eocd))
      (let ((sig (z-read-u4 stream)))
        (unless (= sig +sig-central-directory+)
          (error 'zip-signature-error
                 :expected +sig-central-directory+
                 :actual sig)))
      
      (let* ((version-made-by (z-read-u2 stream))
             (version-needed (z-read-u2 stream))   
             (flags (z-read-u2 stream))           
             (method (z-read-u2 stream))
             (time (z-read-u2 stream))             
             (date (z-read-u2 stream))             
             (crc (z-read-u4 stream))              
             (comp-size (z-read-u4 stream))
             (uncomp-size (z-read-u4 stream))
             (name-len (z-read-u2 stream))
             (extra-len (z-read-u2 stream))
             (comment-len (z-read-u2 stream))
             (disk-start (z-read-u2 stream))      
             (int-attr (z-read-u2 stream))        
             (ext-attr (z-read-u4 stream))        
             (local-offset (z-read-u4 stream)))
             
        (let ((name (z-read-string stream name-len))
              (extra (z-read-string stream extra-len))
              (comment (z-read-string stream comment-len)))
          
          (push (make-zip-entry 
                 :version-made-by version-made-by   
                 :version-needed version-needed     
                 :general-purpose-flag flags        
                 :compression-method method
                 :last-mod-time time                
                 :last-mod-date date                
                 :crc32 crc                         
                 :compressed-size comp-size
                 :uncompressed-size uncomp-size
                 :filename-length name-len          
                 :extra-field-length extra-len      
                 :file-comment-length comment-len   
                 :disk-number-start disk-start      
                 :internal-attributes int-attr  
                 :external-attributes ext-attr          
                 :local-header-offset local-offset
                 :filename name
                 :extra-field extra
                 :comment comment)
                entries))))
    (reverse entries)))

;; ---------------------------------------------------------
;; 6. ФУНКЦИОНАЛЬНОСТЬ: ИЗВЛЕЧЕНИЕ (STORE)
;; ---------------------------------------------------------

(defun verify-local-header (stream entry)
  "Проверяет, что Local File Header согласован с Central Directory."
  (let ((start-pos (z-tell stream)))

    ;; Переходим к Local Header
    (z-seek stream (zip-entry-local-header-offset entry) :set)

    ;; Сигнатура
    (let ((sig (z-read-u4 stream)))
      (unless (= sig +sig-local-file-header+)
        (error 'zip-signature-error
               :expected +sig-local-file-header+
               :actual sig)))

    ;; Пропускаем version-needed и flags
    (z-seek stream 4 :cur)

    ;; Метод сжатия
    (let ((local-method (z-read-u2 stream)))
      (unless (= local-method (zip-entry-compression-method entry))
        (warn "Метод сжатия не совпадает (CD=~A, Local=~A) для файла ~A"
              (zip-entry-compression-method entry)
              local-method
              (zip-entry-filename entry))))

    ;; Пропускаем время, дату, CRC, размеры
    (z-seek stream 12 :cur)

    ;; Имя файла
    (let ((name-len (z-read-u2 stream))
          (extra-len (z-read-u2 stream)))
      (let ((local-name (z-read-string stream name-len)))
        (unless (string= local-name (zip-entry-filename entry))
          (warn "Имя файла не совпадает (CD=~A, Local=~A)"
                (zip-entry-filename entry)
                local-name))))

    ;; Возвращаем позицию
    (z-seek stream start-pos :set)))

(defun extract-file-content (stream entry)
  "Проверка согласованности центрального каталога и локального файла"
  (verify-local-header stream entry)

  (let ((offset (zip-entry-local-header-offset entry))
        (method (zip-entry-compression-method entry))
        (c-size (zip-entry-compressed-size entry)))
    
    ;; 1. Прыгаем к началу Local File Header
    (z-seek stream offset :set)
    
    ;; 2. Проверяем сигнатуру Local Header
    (let ((sig (z-read-u4 stream)))
      (unless (= sig +sig-local-file-header+)
        (error 'zip-signature-error 
               :expected +sig-local-file-header+ 
               :actual sig)))
    
    ;; 3. Пропускаем фиксированную часть заголовка (22 байта), чтобы добраться до длин
    (z-seek stream 22 :cur)
    
    (let ((name-len (z-read-u2 stream))
          (extra-len (z-read-u2 stream)))
      
      ;; 4. Пропускаем имя файла и extra field в локальном заголовке
      (z-seek stream (+ name-len extra-len) :cur)
      
      ;; 5. ТЕПЕРЬ МЫ В НАЧАЛЕ ДАННЫХ
      (let ((raw-data (z-read-byte-array stream c-size)))
        
        ;; 6. Обработка сжатия
        (cond
          ((= method 0) ; Stored (без сжатия)
            raw-data)
          
          ((= method 8) ; Deflate
            (format t ">>> ПРЕДУПРЕЖДЕНИЕ: Метод Deflate (8) пока не реализован. Возвращены сжатые данные.~%")
            raw-data)
          
          (t (error 'zip-error 
                    :message (format nil "Неизвестный метод сжатия: ~A" method))))))))

(defun analyze-zip (zip-data)
  "Главная функция: возвращает структуру zip-archive."
  (let ((stream (make-z-stream :buffer zip-data
                               :pos 0
                               :len (length zip-data))))
    (let ((eocd-pos (find-eocd stream)))
      (unless eocd-pos
        (error 'zip-error :message "Это не ZIP архив"))
      
      (z-seek stream eocd-pos :set)
      (let ((eocd-struct (parse-eocd stream)))
        (let ((files-list (parse-central-directory stream eocd-struct)))
          (make-zip-archive 
           :file-path "memory-buffer"
           :eocd-info eocd-struct
           :files files-list))))))

(defun find-zip-entry (archive filename)
  "Ищет запись файла в архиве по точному имени."
  (find filename (zip-archive-files archive) 
        :key #'zip-entry-filename 
        :test #'string=))

(defun extract-and-verify (stream entry)
  "Извлекает файл и проверяет его на ошибки и целостность."
  (let ((flags (zip-entry-general-purpose-flag entry))
        (expected-crc (zip-entry-crc32 entry)))

    ;; 1. Проверка на шифрование (самый первый бит флагов)
    (when (logbitp 0 flags)
      (error 'zip-error
             :message (format nil "Файл '~A' зашифрован. Пароли пока не поддерживаются." 
                              (zip-entry-filename entry))))

    ;; 2. Само извлечение
    (let ((data (extract-file-content stream entry)))
      
      ;; 3. Проверка CRC (только для несжатых STORE файлов)
      (when (= (zip-entry-compression-method entry) 0)
        (let ((actual-crc (calculate-crc32 data)))
          (unless (= actual-crc expected-crc)
            (warn "Файл '~A' возможно поврежден! CRC mismatch: 0x~X" 
                  (zip-entry-filename entry)
                  actual-crc))))
      data)))

;; ---------------------------------------------------------
;; 7. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ВЫВОДА
;; ---------------------------------------------------------

(defun decode-general-purpose-flags (flags)
  (let ((result '()))
    (dolist (flag *zip-general-purpose-flags*)
      (when (logbitp (first flag) flags)
        (push (second flag) result)))
    (if result
        (reverse result)
        (list "Флаги не установлены"))))

(defun decode-internal-attributes (attr)
  (let ((result '()))
    (when (logbitp 0 attr)
      (push "Текстовый файл" result))
    (when (logbitp 1 attr)
      (push "Управляющая запись" result))
    (if result
        (reverse result)
        (list "Обычный бинарный файл"))))


(defun parse-dos-timestamp (date time)
  "Преобразует упакованные DOS date/time в строку."
  (let ((year  (+ 1980 (ash (logand date #xFE00) -9)))
        (month (ash (logand date #x01E0) -5))
        (day   (logand date #x001F))
        (hour  (ash (logand time #xF800) -11))
        (min   (ash (logand time #x07E0) -5))
        (sec   (* 2 (logand time #x001F))))
    (format nil "~2,'0d.~2,'0d.~4d ~2,'0d:~2,'0d:~2,'0d"
            day month year hour min sec)))

(defun print-tree-view (files)
  "Дополнительная функция: Вывод структуры файлов в виде дерева."
  (format t "~%СТРУКТУРА АРХИВА:~%")
  (format t "root/~%")
  (dolist (f files)
    (let* ((name (zip-entry-filename f))
           (is-dir (char= (char name (1- (length name))) #\/))
           (depth (count #\/ name)))
      ;; Простой визуализатор отступов
      (dotimes (i (1+ depth))
        (format t "  "))
      (if is-dir
          (format t " ~A~%" name)
          (format t " ~A (~A bytes)~%"
                  name
                  (zip-entry-uncompressed-size f))))))

;; ---------------------------------------------------------
;; 8. ГЛАВНАЯ ФУНКЦИЯ ВЫВОДА (КАК В ВАРИАНТЕ 1)
;; ---------------------------------------------------------

(defun print-zip-details-complete (archive zip-data)
  "Выводит полную информацию о архиве: EOCD, все характеристики файлов И их содержимое."

  ;; Создаем поток для чтения содержимого (каждый раз заново)
  (let ((stream (make-z-stream :buffer zip-data :pos 0 :len (length zip-data))))
    
    ;; Выводим информацию EOCD
    (let ((eocd (zip-archive-eocd-info archive)))
      (format t "~%END OF CENTRAL DIRECTORY (EOCD)~%")
      (format t "===============================~%")
      (format t " Номер диска (EOCD):      ~A~%" (zip-eocd-disk-number eocd))
      (format t " Диск начала CD:          ~A~%" (zip-eocd-cd-disk eocd))        
      (format t " Записей на диске:        ~A~%" (zip-eocd-disk-entries eocd))   
      (format t " Всего записей:           ~A~%" (zip-eocd-total-entries eocd))
      (format t " Размер CD:               ~A байт~%" (zip-eocd-cd-size eocd))
      (format t " Смещение начала CD:      ~A~%" (zip-eocd-cd-offset eocd))
      (format t " Длина комментария:       ~A~%" (zip-eocd-comment-len eocd))   
      (format t " Комментарий архива:      ~S~%" (zip-eocd-comment eocd)))

    (print-tree-view (zip-archive-files archive))

    ;; Выводим информацию о каждом файле, включая содержимое
    (let ((files (zip-archive-files archive)))
      (format t "~%~%ЦЕНТРАЛЬНЫЙ КАТАЛОГ (ФАЙЛЫ)~%")
      (format t "===============================~%")
      (loop for file in files
            for i from 1 do
              (format t "~%-------------------------------------------~%")
              (format t "[ФАЙЛ #~A: ~A]~%~%" i (zip-entry-filename file))
            
              ;; Основные характеристики файла
              (format t "ОСНОВНЫЕ ХАРАКТЕРИСТИКИ:~%")
              (format t "   Версия (созд/нужна): ~A / ~A~%" 
                      (zip-entry-version-made-by file) 
                      (zip-entry-version-needed file))
              (format t "   Флаги/Атрибуты        0x~X~%" 
                      (zip-entry-general-purpose-flag file))
              (dolist (f (decode-general-purpose-flags 
                          (zip-entry-general-purpose-flag file)))
              (format t "      - ~A~%" f))

              (dolist (a (decode-internal-attributes
                          (zip-entry-internal-attributes file)))
              (format t "      - ~A~%" a))

              (format t "   CRC32:               0x~X~%" (zip-entry-crc32 file))
              (format t "   Метод сжатия:        ~A~%" (zip-entry-compression-method file))
              (format t "   Дата/Время мод.:     ~A" 
                      (parse-dos-timestamp (zip-entry-last-mod-date file) 
                                           (zip-entry-last-mod-time file))) 
              (format t "~%   Размер (сжат/исх):   ~A / ~A~%" 
                      (zip-entry-compressed-size file) 
                      (zip-entry-uncompressed-size file))
              (format t "   Смещение заголовка:  ~A~%" (zip-entry-local-header-offset file))
              (format t "   Длины (имя/доп/ком): ~A / ~A / ~A~%" 
                      (zip-entry-filename-length file) 
                      (zip-entry-extra-field-length file) 
                      (zip-entry-file-comment-length file))
              (format t "   Диск начала файла:   ~A~%" (zip-entry-disk-number-start file))
              (format t "   Внутр. атрибуты:     0x~X~%" (zip-entry-internal-attributes file))
              
              ;; Поля переменной длины
              (format t "~%ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ:~%")
              (format t "   Доп. поле:           ~S~%" (zip-entry-extra-field file))
              (format t "   Комментарий файла:   ~S~%" (zip-entry-comment file))
              
              ;; СОДЕРЖИМОЕ ФАЙЛА
              (format t "~%СОДЕРЖИМОЕ ФАЙЛА:~%")
              (handler-case
                  (let ((content-bytes (extract-file-content stream file)))
                    ;; Показываем байты в hex
                    (format t "   Данные (Hex): ")
                    (dotimes (j (min 32 (length content-bytes)))
                      (format t "~2,'0x " (aref content-bytes j)))
                    (when (> (length content-bytes) 32)
                      (format t "... (еще ~A байт)" (- (length content-bytes) 32)))
                    (format t "~%")
                    
                    ;; Пытаемся показать как текст
                    (format t "   Текст: \"")
                    (dotimes (j (min 100 (length content-bytes)))
                      (let ((ch (code-char (aref content-bytes j))))
                        (if (or (graphic-char-p ch) (char= ch #\Space) (char= ch #\Newline))
                            (format t "~A" ch)
                            (format t "."))))
                    (when (> (length content-bytes) 100)
                      (format t "..."))
                    (format t "\"~%")
                    
                    ;; Информация о методах сжатия
                    (format t "   Статус извлечения:   ")
                    (cond
                      ((= (zip-entry-compression-method file) 0)
                       (format t "STORED (без сжатия) - ~A байт извлечено~%" 
                               (length content-bytes)))
                      ((= (zip-entry-compression-method file) 8)
                       (format t "DEFLATE (сжатие) - требуется декомпрессия~%"))
                      (t
                       (format t "Неподдерживаемый метод сжатия~%"))))
                (error (e) (format t "!!! ОШИБКА ИЗВЛЕЧЕНИЯ: ~A~%" e)))
              
              (format t "-------------------------------------------~%")))))

;; ---------------------------------------------------------
;; 9. ЗАГРУЗКА И ТЕСТИРОВАНИЕ
;; ---------------------------------------------------------

(defun read-zip-file-into-array (filepath)
  "Читает реальный файл с диска в массив байтов (основной шаг для Memory Stream)."
  (with-open-file (stream filepath 
                          :direction :input 
                          :element-type '(unsigned-byte 8)
                          :if-does-not-exist :error)
    
    (let* ((size (file-length stream))            
           (buffer (make-array size :element-type '(unsigned-byte 8)))) 
      
      (format t "~%~%Чтение файла: ~A (~A байт)...~%" filepath size)
      (read-sequence buffer stream)             
      buffer)))

(defun main-test (filepath)
  "Тестовая функция для запуска парсера."
  (handler-case
      (let* ((zip-data (read-zip-file-into-array filepath))
             (*my-result* (analyze-zip zip-data)))
        (print-zip-details-complete *my-result* zip-data))
    (zip-error (e)
      (format t "~%!!! КРИТИЧЕСКАЯ ОШИБКА АНАЛИЗА ZIP: ~A~%" (zip-error-message e)))
    (error (e)
      (format t "~%!!! ОБЩАЯ ОШИБКА: ~A~%" e))))


(main-test "test_store.zip") 



