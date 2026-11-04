document.addEventListener("DOMContentLoaded", () => {
	document.querySelectorAll("[data-open-dialog]").forEach((button) => {
		button.addEventListener("click", () => {
			const dialog = document.getElementById(button.dataset.openDialog);
			if (!dialog) return;
			if (typeof dialog.showModal === "function") {
				dialog.showModal();
			} else {
				dialog.setAttribute("open", "");
			}
		});
	});

	document.querySelectorAll("[data-close-dialog]").forEach((button) => {
		button.addEventListener("click", () => {
			const dialog = button.closest("dialog");
			if (dialog) dialog.close();
		});
	});

	document.querySelectorAll("dialog").forEach((dialog) => {
		dialog.addEventListener("click", (event) => {
			if (event.target === dialog) dialog.close();
		});
	});

	document.querySelectorAll("form[data-confirm]").forEach((form) => {
		form.addEventListener("submit", (event) => {
			if (!window.confirm(form.dataset.confirm)) {
				event.preventDefault();
			}
		});
	});
});
