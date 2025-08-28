/*
    This file is part of libkleopatra
    SPDX-FileCopyrightText: 2019, 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "animatedexpander.h"

#include <utils/applicationpalettewatcher.h>

#include <QApplication>
#include <QFrame>
#include <QGridLayout>
#include <QParallelAnimationGroup>
#include <QPropertyAnimation>
#include <QProxyStyle>
#include <QStyle>
#include <QToolButton>

using namespace Qt::Literals::StringLiterals;

static const int animationDuration = 300;

class AnimatedExpander::Private
{
public:
    ApplicationPaletteWatcher appPaletteWatcher;
    QGridLayout mainLayout;
    QToolButton toggleButton;
    QFrame headerLine;
    QParallelAnimationGroup toggleAnimation;
    QWidget contentArea;

    int collapsedHeight = -1;
};

void AnimatedExpander::setContentLayout(QLayout *contentLayout)
{
    delete d->contentArea.layout();
    d->contentArea.setLayout(contentLayout);
    // keep top/bottom margins for spacing between header and content
    contentLayout->setContentsMargins(0, contentLayout->contentsMargins().top(), 0, contentLayout->contentsMargins().bottom());
}

bool AnimatedExpander::isExpanded() const
{
    return d->toggleButton.isChecked();
}

void AnimatedExpander::setExpanded(bool expanded)
{
    d->toggleButton.setChecked(expanded);
}

static QString applicationStyleName()
{
    auto style = qApp->style();
    while (auto proxyStyle = qobject_cast<QProxyStyle *>(style)) {
        style = proxyStyle->baseStyle();
    }
    return style ? style->name() : QString{};
}

static void updateToggleButton(QToolButton *toggleButton)
{
    if (applicationStyleName().toLower() == "breeze"_L1) {
        // Breeze draws the focus frame when drawing CE_ToolButtonLabel so that we can simply set the border to none
        toggleButton->setStyleSheet(QStringLiteral("QToolButton { border: none; }"));
    } else {
        // Windows styles (and Qt's common base style) draw the focus frame before drawing CE_ToolButtonLabel which doesn't work with "border: none";
        // instead draw dotted focus frame if button has focus; otherwise, draw invisible frame using background color
        toggleButton->setStyleSheet(
            QStringLiteral("QToolButton { border: 1px solid palette(window); }"
                           "QToolButton:focus { border: 1px dotted palette(window-text); }"));
    }
    toggleButton->setArrowType(toggleButton->isChecked() ? Qt::ArrowType::DownArrow : Qt::ArrowType::RightArrow);
}

AnimatedExpander::AnimatedExpander(const QString &title, const QString &accessibleTitle, QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>()}
{
    d->toggleButton.setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    d->toggleButton.setText(title);
    if (!accessibleTitle.isEmpty()) {
        d->toggleButton.setAccessibleName(accessibleTitle);
    }
    d->toggleButton.setCheckable(true);
    d->toggleButton.setChecked(false);
    updateToggleButton(&d->toggleButton);

    d->headerLine.setFrameShape(QFrame::HLine);
    d->headerLine.setFrameShadow(QFrame::Sunken);
    d->headerLine.setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

    d->contentArea.setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // start out collapsed
    d->contentArea.setMaximumHeight(0);
    d->contentArea.setMinimumHeight(0);
    d->contentArea.setVisible(false);

    // let the entire widget grow and shrink with its content
    d->toggleAnimation.addAnimation(new QPropertyAnimation(this, "minimumHeight"));
    d->toggleAnimation.addAnimation(new QPropertyAnimation(this, "maximumHeight"));
    d->toggleAnimation.addAnimation(new QPropertyAnimation(&d->contentArea, "maximumHeight"));

    d->mainLayout.setVerticalSpacing(0);
    d->mainLayout.setContentsMargins(0, 0, 0, 0);
    int row = 0;
    d->mainLayout.addWidget(&d->toggleButton, row, 0, 1, 1, Qt::AlignLeft);
    d->mainLayout.addWidget(&d->headerLine, row, 2, 1, 1);
    row++;
    d->mainLayout.addWidget(&d->contentArea, row, 0, 1, 3);
    setLayout(&d->mainLayout);
    d->collapsedHeight = sizeHint().height();
    connect(&d->toggleButton, &QToolButton::toggled, this, [this](const bool checked) {
        if (checked) {
            Q_EMIT startExpanding();
            // make the content visible when expanding starts
            d->contentArea.setVisible(true);
        }
        // use instant animation if widget isn't visible (e.g. before widget is shown)
        const int duration = isVisible() ? animationDuration : 0;
        // update the size of the content area
        const auto contentHeight = d->contentArea.layout()->sizeHint().height();
        for (int i = 0; i < d->toggleAnimation.animationCount() - 1; ++i) {
            auto expanderAnimation = static_cast<QPropertyAnimation *>(d->toggleAnimation.animationAt(i));
            expanderAnimation->setDuration(duration);
            expanderAnimation->setStartValue(d->collapsedHeight);
            expanderAnimation->setEndValue(d->collapsedHeight + contentHeight);
        }
        auto contentAnimation = static_cast<QPropertyAnimation *>(d->toggleAnimation.animationAt(d->toggleAnimation.animationCount() - 1));
        contentAnimation->setDuration(duration);
        contentAnimation->setStartValue(0);
        contentAnimation->setEndValue(contentHeight);
        d->toggleButton.setArrowType(checked ? Qt::ArrowType::DownArrow : Qt::ArrowType::RightArrow);
        d->toggleAnimation.setDirection(checked ? QAbstractAnimation::Forward : QAbstractAnimation::Backward);
        d->toggleAnimation.start();
    });
    connect(&d->toggleAnimation, &QAbstractAnimation::finished, this, [this]() {
        // hide the content area when it is fully collapsed
        if (!d->toggleButton.isChecked()) {
            d->contentArea.setVisible(false);
        }
    });
    connect(&d->appPaletteWatcher, &ApplicationPaletteWatcher::paletteChanged, this, [this]() {
        updateToggleButton(&d->toggleButton);
    });
}

AnimatedExpander::~AnimatedExpander() = default;

int AnimatedExpander::contentHeight() const
{
    return d->contentArea.layout()->sizeHint().height();
}

int AnimatedExpander::contentWidth() const
{
    return d->contentArea.layout()->sizeHint().width();
}

#include "moc_animatedexpander.cpp"
