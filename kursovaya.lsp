(defun make-istream (array)
  (list array 0))

(defun get-byte (stream)
  "Чтение байта"
  (let* ((arr (first stream))
         (pos (second stream))
         (len (length arr)))
    (if (< pos len)
        (let ((byte (aref arr pos))
              (new-stream (list arr (1+ pos))))
          (cons byte new-stream))
        (cons nil stream))))

(defun read-2-bytes (stream)
  "Чтение 2-байтного числа"
  (let* ((result1 (get-byte stream))
         (byte1 (car result1))
         (stream2 (cdr result1))
         (result2 (get-byte stream2))
         (byte2 (car result2))
         (stream3 (cdr result2)))
    (if (and byte1 byte2)
        (cons (logior (ash byte2 8) byte1) stream3)
        (cons nil stream))))

(defun read-4-bytes (stream)
  "Чтение 4-байтного числа"
  (let* ((result1 (get-byte stream))
         (byte1 (car result1))
         (stream2 (cdr result1))
         (result2 (get-byte stream2))
         (byte2 (car result2))
         (stream3 (cdr result2))
         (result3 (get-byte stream3))
         (byte3 (car result3))
         (stream4 (cdr result3))
         (result4 (get-byte stream4))
         (byte4 (car result4))
         (stream5 (cdr result4)))
    (if (and byte1 byte2 byte3 byte4)
        (cons (logior (ash byte4 24) (ash byte3 16) (ash byte2 8) byte1) stream5)
        (cons nil stream))))
        
(defvar *zip*
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
  
(defun find-eocd-with-stream (zip-array)
  "Ищет End of Central Directory используя систему потоков"
  (let ((file-size (length zip-array))
        (eocd-signature #x06054B50)  
        (found-pos nil))
    
    (format t "Размер файла: ~A байт~%" file-size)
    
    ;; Идем с конца файла
    (loop for start-pos from (- file-size 4) downto 0
          do (let ((stream (make-istream zip-array)))
               ;; Пропускаем байты до start-pos
               (dotimes (i start-pos)
                 (setf stream (cdr (get-byte stream))))
               
               ;; Читаем 4 байта и проверяем сигнатуру
               (let ((result (read-4-bytes stream)))
                 (when (and (car result) 
                            (= (car result) eocd-signature))
                   (format t "Найдено на позиции ~A!~%" start-pos)
                   (setf found-pos start-pos)
                   (return found-pos)))))
    
    found-pos))

;; Улучшенные функции для работы с потоками
(defun seek-stream (stream position)
  "Установка позиции в потоке"
  (list (first stream) position))

(defun get-position (stream)
  "Получение текущей позиции"
  (second stream))

(defun stream-eof-p (stream)
  "Проверка конца потока"
  (>= (second stream) (length (first stream))))

;; Функции для чтения строк
(defun read-string (stream length)
  "Чтение строки заданной длины"
  (if (<= length 0)
      (cons "" stream)
      (labels ((read-loop (stream length chars)
                 (if (or (<= length 0) (stream-eof-p stream))
                     (cons (coerce (reverse chars) 'string) stream)
                     (let* ((result (get-byte stream))
                            (char (car result))
                            (new-stream (cdr result)))
                       (read-loop new-stream (1- length) (cons (code-char char) chars))))))
        (read-loop stream length '()))))

;; Парсинг End of Central Directory
(defun parse-eocd (stream)
  "Парсинг End of Central Directory Record"
  (format t "~%=== ПАРСИНГ EOCD ===~%")
  (format t "Начальная позиция: ~A~%" (get-position stream))
  
  (let* ((result-signature (read-4-bytes stream))
         (signature (car result-signature))
         (stream (cdr result-signature)))
    
    (format t "Сигнатура: 0x~X~%" signature)
    
    (when (/= signature #x06054b50)
      (error "Неверная сигнатура EOCD: ожидалось 0x6054B50, получили 0x~X" signature))
    
    (let* ((result-disk-number (read-2-bytes stream))
           (disk-number (car result-disk-number))
           (stream (cdr result-disk-number))
           
           (result-cd-disk (read-2-bytes stream))
           (cd-disk (car result-cd-disk))
           (stream (cdr result-cd-disk))
           
           (result-disk-entries (read-2-bytes stream))
           (disk-entries (car result-disk-entries))
           (stream (cdr result-disk-entries))
           
           (result-total-entries (read-2-bytes stream))
           (total-entries (car result-total-entries))
           (stream (cdr result-total-entries))
           
           (result-cd-size (read-4-bytes stream))
           (cd-size (car result-cd-size))
           (stream (cdr result-cd-size))
           
           (result-cd-offset (read-4-bytes stream))
           (cd-offset (car result-cd-offset))
           (stream (cdr result-cd-offset))
           
           (result-comment-len (read-2-bytes stream))
           (comment-len (car result-comment-len))
           (stream (cdr result-comment-len))
           
           (result-comment (read-string stream comment-len))
           (comment (car result-comment))
           (final-stream (cdr result-comment)))
      
      (format t "Номер диска: ~A~%" disk-number)
      (format t "Диск с CD: ~A~%" cd-disk)
      (format t "Записей на диске: ~A~%" disk-entries)
      (format t "Всего записей: ~A~%" total-entries)
      (format t "Размер CD: ~A~%" cd-size)
      (format t "Смещение CD: ~A~%" cd-offset)
      (format t "Длина комментария: ~A~%" comment-len)
      (format t "Комментарий: ~S~%" comment)
      (format t "Конечная позиция: ~A~%" (get-position final-stream))
      
      ;; Возвращаем простой список с ключевыми значениями
      (list cd-offset total-entries))))

(defun find-and-parse-eocd (zip-array)
  "Находит EOCD и парсит его"
  (format t "~%=== ПОИСК И ПАРСИНГ EOCD ===~%")
  (let ((eocd-pos (find-eocd-with-stream zip-array)))
    (if eocd-pos
        (let ((stream (seek-stream (make-istream zip-array) eocd-pos)))
          (format t "EOCD найден на позиции: ~A~%" eocd-pos)
          (parse-eocd stream))
        (progn
          (format t "EOCD не найден!~%")
          nil))))

;; Парсинг Central Directory File Header
(defun parse-central-file-header (stream)
  "Парсинг Central Directory File Header"
  (format t "~%=== ПАРСИНГ ЦЕНТРАЛЬНОГО ЗАГОЛОВКА ФАЙЛА ===~%")
  (format t "Позиция: ~A~%" (get-position stream))
  
  (let* ((result-signature (read-4-bytes stream))
         (signature (car result-signature))
         (stream (cdr result-signature)))
    
    (when (/= signature #x02014b50)
      (error "Неверная сигнатура Central File Header: ожидалось 0x02014B50, получили 0x~X" signature))
    
    (let* ((result-version (read-2-bytes stream))
           (version (car result-version))
           (stream (cdr result-version))
           
           (result-min-version (read-2-bytes stream))
           (min-version (car result-min-version))
           (stream (cdr result-min-version))
           
           (result-flags (read-2-bytes stream))
           (flags (car result-flags))
           (stream (cdr result-flags))
           
           (result-method (read-2-bytes stream))
           (method (car result-method))
           (stream (cdr result-method))
           
           (result-time (read-2-bytes stream))
           (time (car result-time))
           (stream (cdr result-time))
           
           (result-date (read-2-bytes stream))
           (date (car result-date))
           (stream (cdr result-date))
           
           (result-crc (read-4-bytes stream))
           (crc (car result-crc))
           (stream (cdr result-crc))
           
           (result-compressed-size (read-4-bytes stream))
           (compressed-size (car result-compressed-size))
           (stream (cdr result-compressed-size))
           
           (result-uncompressed-size (read-4-bytes stream))
           (uncompressed-size (car result-uncompressed-size))
           (stream (cdr result-uncompressed-size))
           
           (result-name-len (read-2-bytes stream))
           (name-len (car result-name-len))
           (stream (cdr result-name-len))
           
           (result-extra-len (read-2-bytes stream))
           (extra-len (car result-extra-len))
           (stream (cdr result-extra-len))
           
           (result-comment-len (read-2-bytes stream))
           (comment-len (car result-comment-len))
           (stream (cdr result-comment-len))
           
           (result-disk-start (read-2-bytes stream))
           (disk-start (car result-disk-start))
           (stream (cdr result-disk-start))
           
           (result-internal-attr (read-2-bytes stream))
           (internal-attr (car result-internal-attr))
           (stream (cdr result-internal-attr))
           
           (result-external-attr (read-4-bytes stream))
           (external-attr (car result-external-attr))
           (stream (cdr result-external-attr))
           
           (result-local-offset (read-4-bytes stream))
           (local-offset (car result-local-offset))
           (stream (cdr result-local-offset))
           
           ;; Читаем имя файла
           (result-filename (read-string stream name-len))
           (filename (car result-filename))
           (stream (cdr result-filename))
           
           ;; Читаем дополнительные поля
           (result-extra (read-string stream extra-len))
           (extra (car result-extra))
           (stream (cdr result-extra))
           
           ;; Читаем комментарий
           (result-comment (read-string stream comment-len))
           (comment (car result-comment))
           (final-stream (cdr result-comment)))
      
      (format t "Имя файла: ~A~%" filename)
      (format t "Метод сжатия: ~A~%" method)
      (format t "Размер сжатый: ~A~%" compressed-size)
      (format t "Размер исходный: ~A~%" uncompressed-size)
      (format t "Смещение локального заголовка: ~A~%" local-offset)
      (format t "Конечная позиция после чтения: ~A~%" (get-position final-stream))
      
      ;; Возвращаем простой список с информацией о файле
      (list filename method compressed-size uncompressed-size local-offset final-stream))))

(defun read-central-directory (zip-array eocd-info)
  "Чтение центрального каталога"
  (let* ((cd-offset (first eocd-info))
         (total-entries (second eocd-info))
         (stream (seek-stream (make-istream zip-array) cd-offset)))
    (format t "~%=== ЧТЕНИЕ ЦЕНТРАЛЬНОГО КАТАЛОГА ===~%")
    (format t "Смещение: ~A, Всего записей: ~A~%" cd-offset total-entries)
    
    (let ((entries '())
          (current-stream stream))
      (dotimes (i total-entries)
        (let ((entry (parse-central-file-header current-stream)))
          (push entry entries)
          (setf current-stream (sixth entry))
          (format t "Обработана запись ~A из ~A~%" (1+ i) total-entries)))
      (reverse entries))))

;; Основная функция распаковки
(defun unzip (zip-array)
  "Основная функция для распаковки ZIP архива"
  (format t "=== НАЧАЛО РАСПАКОВКИ ZIP АРХИВА ===~%")
  
  ;; 1. Находим и парсим EOCD
  (let ((eocd-info (find-and-parse-eocd zip-array)))
    (when eocd-info
      ;; 2. Читаем центральный каталог
      (let ((central-directory (read-central-directory zip-array eocd-info)))
        (format t "~%=== ОБРАБОТКА ФАЙЛОВ ===~%")
        (format t "Найдено файлов: ~A~%" (length central-directory))
        
        ;; 3. Для каждого файла в центральном каталоге
        (loop for file-entry in central-directory
              for i from 1
              do (let ((filename (first file-entry))
                       (method (second file-entry))
                       (compressed-size (third file-entry))
                       (uncompressed-size (fourth file-entry))
                       (local-offset (fifth file-entry)))
                   
                   (format t "~%--- Файл ~A: ~A ---~%" i filename)
                   (format t "  Метод сжатия: ~A~%" method)
                   (format t "  Сжатый размер: ~A, Исходный размер: ~A~%" compressed-size uncompressed-size)
                   (format t "  Смещение локального заголовка: ~A~%" local-offset))))))
  
  (format t "~%=== РАСПАКОВКА ЗАВЕРШЕНА ===~%"))

;; Тестирование
(defun test-all ()
  "Полное тестирование системы"
  (format t "=== ПОЛНОЕ ТЕСТИРОВАНИЕ БИБЛИОТЕКИ ZIP ===~%")
  
  ;; Тест поиска EOCD
  (format t "~%1. ТЕСТ ПОИСКА EOCD:~%")
  (let ((pos (find-eocd-with-stream *zip*)))
    (if pos
        (format t "Найдена сигнатура через потоки по смещению: ~A (0x~X)~%" pos pos)
        (format t "Сигнатура не найдена!~%")))
  
  ;; Тест парсинга EOCD
  (format t "~%2. ТЕСТ ПАРСИНГА EOCD:~%")
  (let ((eocd-info (find-and-parse-eocd *zip*)))
    (when eocd-info
      (format t "EOCD успешно распарсен!~%")))
  
  ;; Полная распаковка
  (format t "~%3. ПОЛНАЯ РАСПАКОВКА:~%")
  (unzip *zip*))

;; Запуск тестов
(test-all)