;; ==========================================
;; 1. СТРУКТУРЫ И БАЗОВЫЕ ТИПЫ
;; ==========================================

;; Структура потока чтения (наш аналог FILE*)
(defstruct z-stream
  buffer    ; Массив байтов
  pos       ; Текущая позиция (курсор)
  len)      ; Длина массива

;; Структура End of Central Directory (EOCD)
(defstruct zip-eocd
  disk-number      ; Номер диска, содержащего EOCD
  cd-disk          ; Номер диска, на котором начинается Central Directory
  disk-entries     ; Количество записей в CD на этом диске
  total-entries    ; Общее количество записей в CD
  cd-size          ; Размер Центрального Каталога в байтах
  cd-offset        ; Смещение Центрального Каталога относительно начала архива
  comment-len      ; Длина комментария
  comment)         ; Комментарий архива (строка)

;; Структура заголовка файла (из Central Directory)
(defstruct zip-entry
  version-made-by      ; Версия программы, создавшей запись
  version-needed       ; Минимальная версия для извлечения
  general-purpose-flag ; Общие битовые флаги
  compression-method   ; Метод сжатия (0=Stored, 8=Deflate и т.д.)
  last-mod-time        ; Время модификации DOS
  last-mod-date        ; Дата модификации DOS
  crc32                ; Контрольная сумма CRC-32
  compressed-size      ; Сжатый размер
  uncompressed-size    ; Исходный размер
  filename-length      ; Длина имени файла
  extra-field-length   ; Длина доп. поля
  file-comment-length  ; Длина комментария файла
  disk-number-start    ; Номер диска, на котором начинается файл
  internal-attributes  ; Внутренние атрибуты файла
  external-attributes  ; Внешние атрибуты файла
  local-header-offset  ; Смещение Local File Header
  
  ;; Поля переменной длины
  filename             ; Имя файла (строка)
  extra-field          ; Дополнительные поля (строка)
  comment)             ; Комментарий файла (строка)

;; Главная структура архива
(defstruct zip-archive
  file-path
  eocd-info
  files)

;; ==========================================
;; 2. ФУНКЦИИ РАБОТЫ С ПОТОКОМ (STREAM)
;; ==========================================

(defun make-zip-stream (array)
  "Создает структуру потока из массива"
  (make-z-stream :buffer array 
                 :pos 0 
                 :len (length array)))

(defun z-seek (stream offset origin)
  "Аналог fseek. Перемещает курсор."
  (let ((new-pos 0)
        (current (z-stream-pos stream))
        (length (z-stream-len stream)))
    
    (case origin
      (:set (setf new-pos offset))                  
      (:cur (setf new-pos (+ current offset)))      
      (:end (setf new-pos (+ length offset))))      
    
    (when (< new-pos 0) (setf new-pos 0))
    (when (> new-pos length) (setf new-pos length))
    
    (setf (z-stream-pos stream) new-pos)
    new-pos))

(defun z-tell (stream)
  "Возвращает текущую позицию (ftell)"
  (z-stream-pos stream))

(defun z-read-byte (stream)
  "Читает 1 байт и сдвигает курсор"
  (let ((pos (z-stream-pos stream))
        (arr (z-stream-buffer stream)))
    (if (< pos (z-stream-len stream))
        (prog1 
            (aref arr pos)
          (incf (z-stream-pos stream)))
        nil)))

(defun z-read-u2 (stream)
  "Читает 2 байта (Little Endian)"
  (let ((b1 (z-read-byte stream))
        (b2 (z-read-byte stream)))
    (if (and b1 b2)
        (logior (ash b2 8) b1)
        nil)))

(defun z-read-u4 (stream)
  "Читает 4 байта (Little Endian)"
  (let ((b1 (z-read-byte stream))
        (b2 (z-read-byte stream))
        (b3 (z-read-byte stream))
        (b4 (z-read-byte stream)))
    (if (and b1 b2 b3 b4)
        (logior (ash b4 24) (ash b3 16) (ash b2 8) b1)
        nil)))

(defun z-read-string (stream length)
  "Читает строку заданной длины"
  (if (<= length 0)
      ""
      (let ((str (make-string length)))
        (dotimes (i length)
          (setf (char str i) (code-char (z-read-byte stream))))
        str)))

;; [НОВОЕ] Функция для чтения массива байтов (содержимого файла)
(defun z-read-byte-array (stream length)
  "Читает массив байтов заданной длины"
  (let ((arr (make-array length :element-type '(unsigned-byte 8)))
        (src (z-stream-buffer stream))
        (pos (z-stream-pos stream)))
    ;; Простая копия участка массива
    (dotimes (i length)
      (setf (aref arr i) (aref src (+ pos i))))
    ;; Сдвигаем курсор
    (z-seek stream length :cur)
    arr))

;; ==========================================
;; 3. ЛОГИКА ПАРСИНГА ZIP
;; ==========================================

(defun find-eocd (stream)
  "Ищет сигнатуру EOCD, сканируя с конца файла"
  (let ((signature #x06054B50))
    (loop for offset from -22 downto (- -22 65536)
          do (progn
               (z-seek stream offset :end)
               (when (<= (z-tell stream) 0) (return nil))
               (let ((sig (z-read-u4 stream)))
                 (when (and sig (= sig signature))
                   (z-seek stream -4 :cur)
                   (return (z-tell stream))))))))

(defun parse-eocd (stream)
  "Читает структуру EOCD"
  (let ((sig (z-read-u4 stream)))
    (unless (= sig #x06054B50)
      (error "Не найдена сигнатура EOCD")))
  
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
  "Читает центральный каталог, возвращает список структур zip-entry"
  (z-seek stream (zip-eocd-cd-offset eocd) :set)
  
  (let ((entries '()))
    (dotimes (i (zip-eocd-total-entries eocd))
      (let ((sig (z-read-u4 stream)))
        (unless (= sig #x02014B50)
          (error "Ошибка в центральном каталоге: неверная сигнатура")))
      
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

;; ==========================================
;; 4. НОВАЯ ФУНКЦИОНАЛЬНОСТЬ: ИЗВЛЕЧЕНИЕ
;; ==========================================

(defun bytes-to-string (bytes)
  "Вспомогательная функция: преобразует массив байтов в строку"
  (map 'string #'code-char bytes))

(defun extract-file-content (stream entry)
  "Переходит к Local File Header, парсит его и читает данные"
  (let ((offset (zip-entry-local-header-offset entry))
        (method (zip-entry-compression-method entry))
        (c-size (zip-entry-compressed-size entry)))
    
    ;; 1. Прыгаем к началу Local File Header
    (z-seek stream offset :set)
    
    ;; 2. Проверяем сигнатуру Local Header (0x04034B50)
    (let ((sig (z-read-u4 stream)))
      (unless (= sig #x04034B50)
        (error "Ошибка: Неверная сигнатура Local File Header для файла ~A" 
               (zip-entry-filename entry))))
    
    ;; 3. Пропускаем фиксированную часть заголовка (26 байт), 
    ;; т.к. мы уже знаем данные из Центрального Каталога.
    ;; Нам нужны только длины имени и доп. поля, чтобы узнать, где начинаются данные.
    (z-seek stream 22 :cur) ; Пропуск: ver(2)+flags(2)+meth(2)+time(2)+date(2)+crc(4)+csize(4)+usize(4)
    
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
           ;; Здесь должна быть распаковка Deflate. 
           (format t ">>> ПРЕДУПРЕЖДЕНИЕ: Метод Deflate (8) пока не реализован. Возвращены сжатые данные.~%")
           raw-data)
          
          (t (error "Неизвестный метод сжатия: ~A" method)))))))

(defun analyze-zip (zip-data)
  "Главная функция: возвращает структуру zip-archive"
  (let ((stream (make-zip-stream zip-data)))
    (let ((eocd-pos (find-eocd stream)))
      (unless eocd-pos (error "Это не ZIP архив"))
      
      (z-seek stream eocd-pos :set)
      (let ((eocd-struct (parse-eocd stream)))
        (let ((files-list (parse-central-directory stream eocd-struct)))
          (make-zip-archive 
           :file-path "memory-buffer"
           :eocd-info eocd-struct
           :files files-list))))))

;; ==========================================
;; 5. ТЕСТИРОВАНИЕ И ВЫВОД
;; ==========================================

#|(defvar *test-zip*
  #(#x50 #x4b #x03 #x04 #x0a #x00 #x00 #x00 #x00 #x00 #x20 #x88 #x66 #x5b #x68 #x88
  #x52 #xa7 #x06 #x00 #x00 #x00 #x06 #x00 #x00 #x00 #x05 #x00 #x1c #x00 #x74 #x6d
  #x70 #x2f #x31 #x55 #x54 #x09 #x00 #x03 #x1b #xaa #x0c #x69 #x40 #xaa #x0c #x69
  #x75 #x78 #x0b #x00 #x01 #x04 #xe8 #x03 #x00 #x00 #x04 #xe8 #x03 #x00 #x00 #x31
  #x31 #x0a #x32 #x32 #x0a #x50 #x4b #x03 #x04 #x0a #x00 #x00 #x00 #x00 #x00 #x28
  #x88 #x66 #x5b #x37 #xa1 #x8d #xc2 #x06 #x00 #x00 #x00 #x06 #x00 #x00 #x00 #x05
  #x00 #x1c #x00 #x74 #x6d #x70 #x2f #x32 #x55 #x54 #x09 #x00 #x03 #x2c #xaa #x0c
  #x69 #x40 #xaa #x0c #x69 #x75 #x78 #x0b #x00 #x01 #x04 #xe8 #x03 #x00 #x00 #x04
  #xe8 #x03 #x00 #x00 #x33 #x33 #x0a #x34 #x34 #x0a #x50 #x4b #x01 #x02 #x1e #x03
  #x0a #x00 #x00 #x00 #x00 #x00 #x20 #x88 #x66 #x5b #x68 #x88 #x52 #xa7 #x06 #x00
  #x00 #x00 #x06 #x00 #x00 #x00 #x05 #x00 #x18 #x00 #x00 #x00 #x00 #x00 #x00 #x00
  #x00 #x00 #xb4 #x81 #x00 #x00 #x00 #x00 #x74 #x6d #x70 #x2f #x31 #x55 #x54 #x05
  #x00 #x03 #x1b #xaa #x0c #x69 #x75 #x78 #x0b #x00 #x01 #x04 #xe8 #x03 #x00 #x00
  #x04 #xe8 #x03 #x00 #x00 #x50 #x4b #x01 #x02 #x1e #x03 #x0a #x00 #x00 #x00 #x00
  #x00 #x28 #x88 #x66 #x5b #x37 #xa1 #x8d #xc2 #x06 #x00 #x00 #x00 #x06 #x00 #x00
  #x00 #x05 #x00 #x18 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00 #xb4 #x81 #x45
  #x00 #x00 #x00 #x74 #x6d #x70 #x2f #x32 #x55 #x54 #x05 #x00 #x03 #x2c #xaa #x0c
  #x69 #x75 #x78 #x0b #x00 #x01 #x04 #xe8 #x03 #x00 #x00 #x04 #xe8 #x03 #x00 #x00
  #x50 #x4b #x05 #x06 #x00 #x00 #x00 #x00 #x02 #x00 #x02 #x00 #x96 #x00 #x00 #x00
  #x8a #x00 #x00 #x00 #x00 #x00))
|#

(defun read-zip-file-into-array (filepath)
  "Читает реальный файл с диска в массив байтов"
  ;; with-open-file гарантирует, что файл закроется сам после чтения
  (with-open-file (stream filepath 
                          :direction :input 
                          :element-type '(unsigned-byte 8) ;читаем как байты
                          :if-does-not-exist :error)
    
    (let* ((size (file-length stream))            
           (buffer (make-array size :element-type '(unsigned-byte 8)))) 
      
      (format t "~%~%Чтение файла: ~A (~A байт)...~%" filepath size)
      (read-sequence buffer stream)               
      buffer)))                                 

(defvar *test-zip* (read-zip-file-into-array "E:/test.zip"))

(defun parse-dos-timestamp (date time)
  "Преобразует упакованные DOS date/time в список (год месяц день час минута секунда)"
  (let ((year  (+ 1980 (ash (logand date #xFE00) -9)))
        (month (ash (logand date #x01E0) -5))
        (day   (logand date #x001F))
        (hour  (ash (logand time #xF800) -11))
        (min   (ash (logand time #x07E0) -5))
        (sec   (* 2 (logand time #x001F))))
    (format nil "~2,'0d.~2,'0d.~4d ~2,'0d:~2,'0d:~2,'0d" day month year hour min sec)))

(defun print-zip-details-complete (archive zip-data)
  "Выводит полную информацию о архиве: EOCD, все характеристики файлов И их содержимое"
  
  ;; Создаем поток для чтения содержимого
  (let ((stream (make-zip-stream zip-data)))
    
    ;; Выводим информацию EOCD
    (let ((eocd (zip-archive-eocd-info archive)))
      (format t "~%END OF CENTRAL DIRECTORY (EOCD)~%")
      (format t "===============================~%")
      (format t "Номер диска (EOCD):    ~A~%" (zip-eocd-disk-number eocd))
      (format t "Диск начала CD:        ~A~%" (zip-eocd-cd-disk eocd))        
      (format t "Записей на диске:      ~A~%" (zip-eocd-disk-entries eocd))   
      (format t "Всего записей:         ~A~%" (zip-eocd-total-entries eocd))
      (format t "Размер CD:             ~A байт~%" (zip-eocd-cd-size eocd))
      (format t "Смещение начала CD:    ~A~%" (zip-eocd-cd-offset eocd))
      (format t "Длина комментария:      ~A~%" (zip-eocd-comment-len eocd))  
      (format t "Комментарий архива:    ~S~%" (zip-eocd-comment eocd)))

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
              (format t "  Версия (созд/нужна): ~A / ~A~%" 
                      (zip-entry-version-made-by file) 
                      (zip-entry-version-needed file))
              (format t "  Флаги/Атрибуты:      0x~X / 0x~X~%" 
                      (zip-entry-general-purpose-flag file) 
                      (zip-entry-external-attributes file))
              (format t "  CRC32:               0x~X~%" (zip-entry-crc32 file))
              (format t "  Метод сжатия:        ~A~%" (zip-entry-compression-method file))
              (format t "  Дата/Время мод.:     ~A" 
                      (parse-dos-timestamp (zip-entry-last-mod-date file) 
                      (zip-entry-last-mod-time file))) 
              (format t "~%  Размер (сжат/исх):   ~A / ~A~%" 
                      (zip-entry-compressed-size file) 
                      (zip-entry-uncompressed-size file))
              (format t "  Смещение заголовка:  ~A~%" (zip-entry-local-header-offset file))
              (format t "  Длины (имя/доп/ком): ~A / ~A / ~A~%" 
                      (zip-entry-filename-length file) 
                      (zip-entry-extra-field-length file) 
                      (zip-entry-file-comment-length file))
              (format t "  Диск начала файла:   ~A~%" (zip-entry-disk-number-start file))
              (format t "  Внутр. атрибуты:     0x~X~%" (zip-entry-internal-attributes file))
              
              ;; Поля переменной длины
              (format t "~%ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ:~%")
              (format t "  Доп. поле:           ~S~%" (zip-entry-extra-field file))
              (format t "  Комментарий файла:   ~S~%" (zip-entry-comment file))
              
              ;; СОДЕРЖИМОЕ ФАЙЛА
              (format t "~%СОДЕРЖИМОЕ ФАЙЛА:~%")
              (let ((content-bytes (extract-file-content stream file)))
                ;; Показываем байты в hex
                (format t "  Данные (Hex): ")
                (dotimes (j (min 32 (length content-bytes)))
                  (format t "~2,'0x " (aref content-bytes j)))
                (when (> (length content-bytes) 32)
                  (format t "... (еще ~A байт)" (- (length content-bytes) 32)))
                (format t "~%")
                
                ;; Пытаемся показать как текст
                (format t "  Текст: \"")
                (dotimes (j (min 100 (length content-bytes)))
                  (let ((ch (code-char (aref content-bytes j))))
                    (if (or (graphic-char-p ch) (char= ch #\Space))
                        (format t "~A" ch)
                        (format t "."))))
                (when (> (length content-bytes) 100)
                  (format t "..."))
                (format t "\"~%")
                
                ;; Информация о методах сжатия
                (format t "  Статус извлечения:  ")
                (cond
                  ((= (zip-entry-compression-method file) 0)
                   (format t "STORED (без сжатия) - ~A байт извлечено~%" 
                           (length content-bytes)))
                  ((= (zip-entry-compression-method file) 8)
                   (format t "DEFLATE (сжатие) - требуется декомпрессия~%"))
                  (t
                   (format t "Неподдерживаемый метод сжатия~%"))))
              
              (format t "-------------------------------------------~%")))))

;; Запуск
(format t "Запуск анализатора ZIP...~%")
(defparameter *my-result* (analyze-zip *test-zip*))
(print-zip-details-complete *my-result* *test-zip*)