import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import asyncio

class QwenRunner:
    def __init__(self, model_id="Qwen/Qwen2.5-0.5B-Instruct"):
        self.model_id = model_id
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Loading {model_id} on {self.device}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16 if self.device == "cuda" else torch.float32,
            device_map="auto"
        )
        print("Model loaded successfully.")

    async def generate_response(self, prompt: str, system_prompt: str = "") -> str:
        # Chạy trong một luồng riêng để không block FastAPI
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._generate, prompt, system_prompt)

    def _generate(self, prompt: str, system_prompt: str) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        text = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)

        generated_ids = self.model.generate(
            **model_inputs,
            max_new_tokens=256,
            temperature=0.3,
            do_sample=True,
            top_p=0.9
        )
        
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]
        
        response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
        return response
