const paymentMessage = document.getElementById("paymentMessage");
const token = localStorage.getItem("choicewise_token");

async function checkCredits() {
  try {
    if (!token) {
      paymentMessage.textContent =
        "Payment completed. Please login again to check your credits.";
      return;
    }

    const response = await fetch("/api/account/usage", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Could not check account credits.");
    }

    paymentMessage.textContent =
      `Your current paid scan credits: ${data.usage.paidScanCredits}. If your new credits are not showing yet, refresh after a minute.`;
  } catch (error) {
    paymentMessage.textContent = error.message;
  }
}

checkCredits();