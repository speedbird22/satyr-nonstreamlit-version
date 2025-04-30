
import streamlit as st

def chat_ui():
    st.title("🤖 SATyr Chat Interface")
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    user_input = st.text_input("You:", key="user_input")
    if st.button("Send") and user_input.strip() != "":
        st.session_state.chat_history.append(("You", user_input))
        response = f"SATyr says: I'm still learning! You said: {user_input}"
        st.session_state.chat_history.append(("SATyr", response))
        st.session_state.user_input = ""

    st.markdown("---")
    for speaker, message in reversed(st.session_state.chat_history):
        with st.chat_message(speaker.lower() if speaker != "SATyr" else "assistant"):
            st.markdown(message)
