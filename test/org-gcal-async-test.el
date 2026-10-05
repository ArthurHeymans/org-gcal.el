;;; org-gcal-async-test.el --- Async authentication tests -*- lexical-binding: t -*-

(require 'ert)
(require 'cl-lib)
(require 'org-gcal)

(ert-deftest org-gcal-test--requests-wait-for-token-asynchronously ()
  "Every request path must yield while authentication is pending."
  (dolist (operation '(events instances get post delete))
    (with-temp-buffer
      (let* ((promise (aio-promise))
             (marker (point-marker))
             (token-calls 0)
             requests
             (org-gcal--sync-tokens nil))
        (cl-letf (((symbol-function 'oauth2-auto-access-token)
                   (lambda (calendar-id provider)
                     (should (equal calendar-id "calendar"))
                     (should (eq provider 'org-gcal))
                     (cl-incf token-calls)
                     promise))
                  ((symbol-function 'request-deferred)
                   (lambda (url &rest args)
                     (push (cons url args) requests)
                     (deferred:succeed
                      (make-request-response :status-code 200))))
                  ((symbol-function 'org-gcal--update-entry) #'ignore)
                  ((symbol-function 'org-gcal--notify) #'ignore))
          (let ((result
                 (pcase operation
                   ('events (org-gcal--sync-request-events
                             "calendar" nil (current-time) (current-time)))
                   ('instances (org-gcal--sync-request-instances
                                "calendar" "event" (current-time) (current-time) nil))
                   ('get (org-gcal--get-event "calendar" "event"))
                   ('post (org-gcal--post-event
                           "2026-01-01" "2026-01-02" "Summary" nil nil nil
                           "calendar" marker "opaque"))
                   ('delete (org-gcal--delete-event "calendar" "event" nil marker)))))
            (should (deferred-p result))
            (deferred:flush-queue!)
            (should (= token-calls 1))
            (should-not requests)
            ;; An unrelated timer can run before authentication completes.
            (should (eq 'heartbeat (aio-wait-for (aio-sleep 0.01 'heartbeat))))
            (should-not requests)
            (aio-resolve promise (lambda () "token"))
            (deferred:sync! result)
            (should (= (length requests) 1))
            (should (= token-calls 1))
            (should (equal
                     (cdr (assoc "Authorization"
                                 (plist-get (cdar requests) :headers)))
                     "Bearer token"))
            (when (memq operation '(events instances))
              (should (equal
                       (cdr (assoc "access_token"
                                   (plist-get (cdar requests) :params)))
                       "token")))
            (when (memq operation '(post delete))
              (should-not (marker-buffer marker)))))))))

(ert-deftest org-gcal-test--token-errors-propagate-and-release-markers ()
  "Authentication failures must reach callers and run marker cleanup."
  (dolist (operation '(get post delete))
    (with-temp-buffer
      (let ((promise (aio-promise))
            (marker (point-marker)))
        (cl-letf (((symbol-function 'oauth2-auto-access-token)
                   (lambda (&rest _) promise))
                  ((symbol-function 'request-deferred)
                   (lambda (&rest _) (ert-fail "Request before authentication"))))
          (let ((result
                 (pcase operation
                   ('get (org-gcal--get-event "calendar" "event"))
                   ('post (org-gcal--post-event
                           "2026-01-01" "2026-01-02" "Summary" nil nil nil
                           "calendar" marker "opaque"))
                   ('delete (org-gcal--delete-event "calendar" "event" nil marker)))))
            (deferred:flush-queue!)
            (aio-resolve promise (lambda () (error "Authentication failed")))
            (should-error (deferred:sync! result) :type 'error)
            (when (memq operation '(post delete))
              (should-not (marker-buffer marker)))))))))

(ert-deftest org-gcal-test--token-startup-error-propagates ()
  "Errors raised before a promise is returned must not escape the chain."
  (cl-letf (((symbol-function 'oauth2-auto-access-token)
             (lambda (&rest _) (error "Cannot start authentication"))))
    (let ((result (org-gcal--get-access-token "calendar")))
      (should (deferred-p result))
      (should-error (deferred:sync! result) :type 'error))))

(ert-deftest org-gcal-test--http-401-refreshes-asynchronously ()
  "HTTP 401 retries must wait for the replacement token without blocking."
  (let ((replacement (aio-promise))
        (token-calls 0)
        (request-calls 0))
    (cl-letf (((symbol-function 'oauth2-auto-access-token)
               (lambda (&rest _)
                 (cl-incf token-calls)
                 (if (= token-calls 1)
                     (aio-sleep 0 "expired")
                   replacement)))
              ((symbol-function 'request-deferred)
               (lambda (_url &rest args)
                 (cl-incf request-calls)
                 (should (equal
                          (cdr (assoc "Authorization" (plist-get args :headers)))
                          (if (= request-calls 1) "Bearer expired" "Bearer fresh")))
                 (deferred:succeed
                  (make-request-response
                   :status-code (if (= request-calls 1) 401 200)))))
              ((symbol-function 'org-gcal--notify) #'ignore))
      (let ((result (org-gcal--get-event "calendar" "event"))
            (completion (aio-promise)))
        (deferred:error
          (deferred:nextc result
            (lambda (response) (aio-resolve completion (lambda () response))))
          (lambda (err)
            (aio-resolve completion (lambda () (signal (car err) (cdr err))))))
        (let ((deadline (+ (float-time) 2)))
          (while (and (< token-calls 2) (< (float-time) deadline))
            (accept-process-output nil 0.01)))
        (should (= token-calls 2))
        (should (= request-calls 1))
        (aio-resolve replacement (lambda () "fresh"))
        (should (= (request-response-status-code (aio-wait-for completion)) 200))
        (should (= request-calls 2))))))

(ert-deftest org-gcal-test--sync-unlocks-after-authentication-error ()
  "A failed asynchronous token lookup must release the sync lock."
  (let ((org-gcal--sync-lock nil)
        (org-gcal-auto-archive nil)
        (org-gcal-fetch-file-alist '(("calendar" . "unused.org")))
        (promise (aio-promise)))
    (cl-letf (((symbol-function 'org-generic-id-update-id-locations) #'ignore)
              ((symbol-function 'oauth2-auto-access-token)
               (lambda (&rest _) promise)))
      (let ((result (org-gcal-sync t t)))
        (should org-gcal--sync-lock)
        (deferred:flush-queue!)
        (aio-resolve promise (lambda () (error "Authentication failed")))
        (should-error (deferred:sync! result))
        (should-not org-gcal--sync-lock)))))

(ert-deftest org-gcal-test--event-import-yields-and-preserves-order ()
  "Process one event per event-loop turn and collect existing entries in order."
  (with-temp-buffer
    (let ((buffer (current-buffer))
          (heartbeat nil)
          seen)
      (cl-letf (((symbol-function 'find-file-noselect) (lambda (&rest _) buffer))
                ((symbol-function 'org-gcal--sync-handle-event)
                 (lambda (_calendar-id event &rest _)
                   (should (eq (current-buffer) buffer))
                   (push event seen)
                   (if (= event 1)
                       (run-at-time 0 nil (lambda () (setq heartbeat t)))
                     (should heartbeat))
                   (unless (= event 2) event))))
        (let ((result (org-gcal--sync-handle-events
                       "calendar" "unused.org" [1 2 3] nil nil nil nil)))
          (should-not seen)
          (should (equal (deferred:sync! result) '(1 3)))
          (should (equal (nreverse seen) '(1 2 3))))))))

(ert-deftest org-gcal-test--buffer-sync-waits-and-advances ()
  "Await posting before advancing, then visit each drawer exactly once."
  (with-temp-buffer
    (org-mode)
    (insert "* First\n:org-gcal:\nText\n:END:\n"
            "* Second\n:org-gcal:\nText\n:END:\n"
            "* Third\n:org-gcal:\nText\n:END:\n")
    (let ((pending (deferred:new))
          (completion (aio-promise))
          posted)
      (cl-letf (((symbol-function 'org-gcal--get-time-and-desc) (lambda () nil))
                ((symbol-function 'org-gcal-post-at-point)
                 (lambda (&rest _)
                   (push (org-get-heading t t t t) posted)
                   (if (= (length posted) 1) pending (deferred:succeed nil)))))
        (deferred:error
          (deferred:nextc
           (org-gcal--sync-buffer-inner t t nil nil (point-min-marker))
           (lambda (_) (aio-resolve completion (lambda () t))))
          (lambda (err)
            (aio-resolve completion (lambda () (signal (car err) (cdr err))))))
        (let ((deadline (+ (float-time) 2)))
          (while (and (not posted) (< (float-time) deadline))
            (accept-process-output nil 0.01)))
        (should (equal posted '("First")))
        (should-not (aio-result completion))
        (deferred:callback-post pending nil)
        (should (aio-wait-for completion))
        (should (equal (nreverse posted) '("First" "Second" "Third")))))))

(ert-deftest org-gcal-test--buffer-sync-skips-unmanaged-entries ()
  "Filtering entries must advance asynchronously rather than loop in place."
  (with-temp-buffer
    (org-mode)
    (insert "* First\n:org-gcal:\nText\n:END:\n"
            "* Second\n:org-gcal:\nText\n:END:\n")
    (cl-letf (((symbol-function 'org-gcal--get-time-and-desc) (lambda () nil))
              ((symbol-function 'org-gcal-post-at-point)
               (lambda (&rest _) (ert-fail "Unmanaged entry posted"))))
      (should-not
       (deferred:sync!
        (org-gcal--sync-buffer-inner t t nil t (point-min-marker)))))))

(ert-deftest org-gcal-test--agenda-sync-advances-source-markers ()
  "Agenda syncing must advance agenda lines while posting source entries."
  (with-temp-buffer
    (org-mode)
    (insert "* First\n:org-gcal:\nText\n:END:\n"
            "* Second\n:org-gcal:\nText\n:END:\n")
    (goto-char (point-min))
    (let ((first (point-marker))
          (second (progn (outline-next-heading) (point-marker)))
          posted)
      (with-temp-buffer
        (setq major-mode 'org-agenda-mode)
        (insert "Agenda header\n"
                (propertize "First\n" 'org-hd-marker first)
                (propertize "Second\n" 'org-hd-marker second))
        (cl-letf (((symbol-function 'org-gcal--get-time-and-desc) (lambda () nil))
                  ((symbol-function 'org-gcal-post-at-point)
                   (lambda (&rest _)
                     (push (org-get-heading t t t t) posted)
                     (deferred:succeed nil))))
          (deferred:sync!
           (org-gcal--sync-buffer-inner t t nil nil (point-min-marker)))
          (should (equal (nreverse posted) '("First" "Second"))))))))

(ert-deftest org-gcal-test--sync-lock-covers-fetch-and-buffer-updates ()
  "Keep the sync lock until both fetching and buffer updates finish."
  (with-temp-buffer
    (let ((buffer (current-buffer))
          (org-gcal--sync-lock nil)
          (org-gcal-auto-archive nil)
          (org-gcal-fetch-file-alist '(("calendar" . "unused.org")))
          (fetch (deferred:new))
          (update (deferred:new))
          (completion (aio-promise))
          updating)
      (cl-letf (((symbol-function 'org-generic-id-update-id-locations) #'ignore)
                ((symbol-function 'org-gcal--sync-calendar) (lambda (&rest _) fetch))
                ((symbol-function 'org-generic-id-files) (lambda () '("unused.org")))
                ((symbol-function 'find-file-noselect) (lambda (&rest _) buffer))
                ((symbol-function 'org-gcal--sync-buffer-inner)
                 (lambda (_skip _silent _date _managed marker)
                   (set-marker marker nil)
                   (setq updating t)
                   update)))
        (deferred:nextc (org-gcal-sync t t)
          (lambda (_) (aio-resolve completion (lambda () t))))
        (deferred:flush-queue!)
        (should org-gcal--sync-lock)
        (should-not updating)
        (should-not (aio-result completion))
        (deferred:callback-post fetch nil)
        (deferred:flush-queue!)
        (should updating)
        (should org-gcal--sync-lock)
        (should-not (aio-result completion))
        (deferred:callback-post update nil)
        (should (aio-wait-for completion))
        (should-not org-gcal--sync-lock)))))

(provide 'org-gcal-async-test)
;;; org-gcal-async-test.el ends here
