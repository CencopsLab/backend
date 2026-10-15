const assert = require('node:assert/strict');
const test = require('node:test');
const { INVENTORY, QUESTION_COUNT, SCAM_TYPES, checkAnswer, localizedQuestion, sampleQuestions } = require('../src/quiz');

test('each scam type has 50 unique story questions and no answer option is reused', () => {
  for (const type of Object.keys(SCAM_TYPES)) {
    const questions = INVENTORY[type];
    assert.equal(questions.length, 50);
    assert.equal(new Set(questions.map((question) => question.id)).size, 50);
    assert.equal(new Set(questions.map((question) => question.story)).size, 50);
    for (const language of ['en', 'hi', 'pa']) {
      const options = questions.flatMap((question) =>
        localizedQuestion(question, language).options
      );
      assert.equal(options.length, 200);
      assert.equal(new Set(options).size, 200, `${type} has a repeated ${language} option`);
    }
    assert.equal(new Set(questions.map((question) => question.answerIndex)).size, 4);
  }
});

test('returns ten unique random questions without exposing answers', () => {
  const questions = sampleQuestions('link', 'en', (min, max) => min % (max - min) + min);

  assert.equal(questions.length, QUESTION_COUNT);
  assert.equal(new Set(questions.map((question) => question.id)).size, QUESTION_COUNT);
  for (const question of questions) {
    assert.equal(question.options.length, 4);
    assert.equal(Object.hasOwn(question, 'answerIndex'), false);
    assert.equal(Object.hasOwn(question, 'answerVariantIndex'), false);
    assert.equal(Object.hasOwn(question, 'explanation'), false);
  }
});

test('correct-answer wording and selected answer choices vary across questions', () => {
  for (const type of Object.keys(SCAM_TYPES)) {
    const questions = sampleQuestions(type, 'en', (min) => min);
    assert.equal(new Set(questions.map((question) => question.options.join('|'))).size, QUESTION_COUNT);
    assert.equal(new Set(questions.map((question) => {
      const entry = INVENTORY[type].find((item) => item.id === question.id);
      return question.options[entry.answerIndex];
    })).size, QUESTION_COUNT);
  }
});

test('checks the correct answer and rejects question IDs from another scam type', () => {
  for (const [type, questions] of Object.entries(INVENTORY)) {
    for (const question of questions) {
      const correct = checkAnswer(type, question.id, question.answerIndex);
      const incorrect = checkAnswer(type, question.id, (question.answerIndex + 1) % 4);
      assert.equal(correct.correct, true);
      assert.equal(correct.correctAnswer, question.options[question.answerIndex]);
      assert.equal(typeof correct.explanation, 'string');
      assert.equal(incorrect.correct, false);
    }
  }
  const question = INVENTORY.sms[0];
  assert.equal(checkAnswer('email', question.id, question.answerIndex), null);
  assert.equal(sampleQuestions('unknown'), null);
});

test('localizes each scam type question and answer in Hindi and Punjabi', () => {
  for (const type of Object.keys(SCAM_TYPES)) {
    for (const language of ['hi', 'pa']) {
      const question = sampleQuestions(type, language)[0];
      assert.match(question.story, /[^\x00-\x7F]/);
      assert.equal(question.options.length, 4);
      assert.equal(question.question.length > 0, true);
      assert.equal(Object.hasOwn(question, 'answerIndex'), false);
      assert.equal(Object.hasOwn(question, 'answerVariantIndex'), false);
      const questionEntry = INVENTORY[type].find((item) => item.id === question.id);
      const answer = checkAnswer(type, question.id, questionEntry.answerIndex, language);
      assert.equal(answer.correct, true);
      assert.equal(answer.correctAnswer, question.options[questionEntry.answerIndex]);
      assert.match(answer.explanation, /[^\x00-\x7F]/);
    }
  }
});
