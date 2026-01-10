import React, { useEffect, useState } from "react";
import { Modal, TextArea, InlineNotification } from "@carbon/react";

/**
 * Simple JSON editor modal.
 * - No external dependencies
 * - Validation happens on save
 */
export default function JsonModal({
  open,
  title,
  initialValue,
  primaryButtonText = "Save",
  secondaryButtonText = "Cancel",
  onClose,
  onSave,
}) {
  const [text, setText] = useState("{}");
  const [err, setErr] = useState(null);

  useEffect(() => {
    if (open) {
      setErr(null);
      setText(typeof initialValue === "string" ? initialValue : JSON.stringify(initialValue ?? {}, null, 2));
    }
  }, [open, initialValue]);

  const handleSave = () => {
    try {
      const parsed = JSON.parse(text || "{}");
      setErr(null);
      onSave?.(parsed);
    } catch (e) {
      setErr("JSON is invalid. Please fix syntax and try again.");
    }
  };

  return (
    <Modal
      open={open}
      modalHeading={title}
      primaryButtonText={primaryButtonText}
      secondaryButtonText={secondaryButtonText}
      onRequestClose={onClose}
      onRequestSubmit={handleSave}
      size="lg"
    >
      {err ? (
        <InlineNotification
          kind="error"
          title="Invalid JSON"
          subtitle={err}
          lowContrast
          style={{ marginBottom: 12 }}
        />
      ) : null}

      <TextArea
        labelText=""
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={18}
        style={{ width: "100%" }}
      />
    </Modal>
  );
}
